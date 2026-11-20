// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Rule matching, conservative constant filtering, deterministic ordering, and de-duplication.
 *
 * Matching is layered by evidence strength (`exact_signature` > `type_inferred` > `name_only` >
 * `structural`); a same-named call is never silently promoted to a well-known API. Filtering only
 * ever *removes* a candidate the rule itself allows removing, and only when the sensitive input is
 * provably constant; every uncertain case is retained.
 */

import { constStateFromEval, evaluateFormatTransform, evaluateSensitive } from './constants.js';
import { fullyQualifiedName, type LoadedRuleSet } from './rules.js';
import type {
  CandidateRole,
  ConstState,
  FileIndexEntry,
  MatchConfidence,
  NormalizedRule,
  RawIndexFile,
  RawSite,
  SecurityCandidate,
  VulnerabilityType,
} from './types.js';
import { MAX_CANDIDATE_CODE_LENGTH } from './types.js';

const CONFIDENCE_RANK: Readonly<Record<MatchConfidence, number>> = {
  exact_signature: 0,
  structural: 1,
  type_inferred: 2,
  name_only: 3,
};

const SOURCE_ORDER: readonly VulnerabilityType[] = ['injection', 'xss', 'ssrf', 'auth', 'authz'];

const CATEGORY_PREFERENCES: Readonly<Record<VulnerabilityType, readonly string[]>> = {
  injection: [
    'sql',
    'command',
    'path',
    'template',
    'expression',
    'deserialization',
    'url_request',
    'http_request',
    'spring_binding',
    'env_source',
    'format',
    'custom_function',
  ],
  xss: ['xss_output', 'http_request', 'spring_binding', 'format', 'http_route', 'authz_check', 'custom_function'],
  ssrf: ['url_request', 'http_request', 'env_source', 'spring_binding', 'custom_function'],
  auth: [
    'auth_source',
    'auth_boundary',
    'http_route',
    'http_request',
    'spring_binding',
    'authz_check',
    'custom_function',
  ],
  authz: [
    'authz_check',
    'authz_config',
    'http_route',
    'auth_source',
    'http_request',
    'spring_binding',
    'custom_function',
  ],
};

interface ResolvedType {
  readonly simple: string;
  readonly fqcn?: string;
}

function stripTypeText(typeText: string): string {
  const noGenerics = typeText.split('<')[0] ?? typeText;
  return noGenerics.replace(/\[\]/g, '').replace(/\s+/g, ' ').trim();
}

function resolveType(file: FileIndexEntry, typeText: string): ResolvedType {
  const base = stripTypeText(typeText);
  const simple = base.slice(base.lastIndexOf('.') + 1);
  if (base.includes('.')) return { simple, fqcn: base };
  const imported = file.imports[simple];
  if (imported !== undefined) return { simple, fqcn: imported };
  if (/^[A-Z]/.test(simple)) return { simple, fqcn: `java.lang.${simple}` };
  return { simple };
}

function lookupDeclaredType(
  file: FileIndexEntry,
  symbol: string | undefined,
  name: string | undefined,
): string | undefined {
  if (name === undefined) return undefined;
  if (symbol !== undefined) {
    const local = file.locals[symbol]?.[name];
    if (local?.declaredType !== undefined) return local.declaredType;
  }
  return file.fields[name];
}

function resolveReceiver(file: FileIndexEntry, site: RawSite): ResolvedType | undefined {
  const shape = site.receiverShape;
  const root = site.receiverRoot;
  if (shape === 'identifier' && root !== undefined) {
    const declared = lookupDeclaredType(file, site.symbol, root);
    if (declared !== undefined) return resolveType(file, declared);
    if (/^[A-Z]/.test(root)) return resolveType(file, root);
    return undefined;
  }
  if (shape === 'static_call' && root !== undefined) return resolveType(file, root);
  if (shape === 'new' && root !== undefined) return resolveType(file, root);
  // Chained receivers (`response.getWriter().write`) have the return type of the last call, which
  // is unknown without symbol resolution. Do not guess from the root object.
  return undefined;
}

interface SiteMatch {
  readonly confidence: MatchConfidence;
  readonly resolvedApi?: string;
  /** True when only the method name is known, so the rule's receiver type is unproven. */
  readonly weak?: boolean;
}

function matchCall(site: RawSite, file: FileIndexEntry, rule: NormalizedRule): SiteMatch | undefined {
  if (rule.match.method === undefined || rule.match.method !== site.methodName) return undefined;
  if (rule.match.arity !== undefined && rule.match.arity !== site.argCount) return undefined;
  const ruleClass = rule.match.class;
  if (ruleClass === undefined) return { confidence: 'name_only' };
  const ruleFqcn = fullyQualifiedName(rule);
  const resolved = resolveReceiver(file, site);
  if (resolved === undefined) return { confidence: 'name_only', weak: true };
  if (ruleFqcn !== undefined && resolved.fqcn === ruleFqcn) {
    if (rule.match.match_subtypes === true) {
      return {
        confidence: 'type_inferred',
        ...(ruleFqcn !== undefined && { resolvedApi: `${ruleFqcn}.${site.methodName ?? ''}` }),
      };
    }
    return {
      confidence: 'exact_signature',
      ...(ruleFqcn !== undefined && { resolvedApi: `${ruleFqcn}.${site.methodName ?? ''}` }),
    };
  }
  if (resolved.simple === ruleClass) {
    return {
      confidence: 'type_inferred',
      ...(resolved.fqcn !== undefined && { resolvedApi: `${resolved.fqcn}.${site.methodName ?? ''}` }),
    };
  }
  return undefined;
}

function matchConstructor(site: RawSite, file: FileIndexEntry, rule: NormalizedRule): SiteMatch | undefined {
  if (rule.match.class === undefined || site.typeName === undefined) return undefined;
  const resolved = resolveType(file, site.typeName);
  const ruleFqcn = fullyQualifiedName(rule);
  if (resolved.fqcn !== undefined && ruleFqcn !== undefined && resolved.fqcn === ruleFqcn) {
    return { confidence: 'exact_signature', resolvedApi: ruleFqcn };
  }
  if (resolved.simple === rule.match.class) {
    return { confidence: 'type_inferred', ...(resolved.fqcn !== undefined && { resolvedApi: resolved.fqcn }) };
  }
  return undefined;
}

function matchAnnotation(site: RawSite, rule: NormalizedRule): SiteMatch | undefined {
  if (rule.match.annotation_name === undefined || site.annotationName === undefined) return undefined;
  if (rule.match.annotation_name !== site.annotationName) return undefined;
  return { confidence: 'structural' };
}

function matchSite(site: RawSite, file: FileIndexEntry, rule: NormalizedRule): SiteMatch | undefined {
  switch (rule.match.kind) {
    case 'method_call':
      return site.kind === 'call' ? matchCall(site, file, rule) : undefined;
    case 'constructor':
      return site.kind === 'constructor' ? matchConstructor(site, file, rule) : undefined;
    case 'annotation':
      return site.kind === 'annotation' ? matchAnnotation(site, rule) : undefined;
    default:
      return undefined;
  }
}

function functionText(site: RawSite): string {
  if (site.kind === 'call') {
    const receiver = site.receiverText;
    return receiver !== undefined && receiver.length > 0
      ? `${receiver}.${site.methodName ?? ''}`
      : (site.methodName ?? '');
  }
  if (site.kind === 'constructor') return `new ${site.typeName ?? ''}`;
  if (site.kind === 'annotation') return `@${site.annotationName ?? ''}`;
  return site.methodName ?? '';
}

function truncateCode(code: string): string {
  return code.length > MAX_CANDIDATE_CODE_LENGTH ? `${code.slice(0, MAX_CANDIDATE_CODE_LENGTH - 1)}…` : code;
}

interface MutableCandidate {
  role: CandidateRole;
  vulnerabilityTypes: Set<VulnerabilityType>;
  category: string;
  file: string;
  line: number;
  column: number;
  symbol?: string;
  function: string;
  resolvedApi?: string;
  confidence: MatchConfidence;
  code: string;
  constantState: ConstState;
  reason: string;
  ruleIds: string[];
}

function constantStateFor(rule: NormalizedRule, site: RawSite, file: FileIndexEntry): ConstState {
  if (rule.constant_filter === 'format_aware' && rule.role === 'transform') {
    return evaluateFormatTransform(site, file).state;
  }
  if (rule.constant_filter === 'never' && rule.sensitive.target === 'argument') {
    // Still report the informational state for never-filtered argument rules.
    return constStateFromEval(evaluateSensitive(rule, site, file).details[0] ?? { state: 'dynamic' });
  }
  return evaluateSensitive(rule, site, file).state;
}

function shouldFilter(rule: NormalizedRule, site: RawSite, file: FileIndexEntry, confidence: MatchConfidence): boolean {
  if (rule.constant_filter === 'never') return false;
  // Never drop a candidate whose receiver type is unproven: constant arguments to a same-named
  // method are not evidence that an *unclassified* call is safe.
  if (confidence === 'name_only') return false;
  if (rule.constant_filter === 'format_aware') {
    if (rule.role !== 'transform') return false;
    return evaluateFormatTransform(site, file).state === 'constant';
  }
  const evaluation = evaluateSensitive(rule, site, file);
  if (evaluation.state !== 'constant') return false;
  // Only argument/receiver/annotation targets describe a real sensitive input we may drop on.
  const target = rule.sensitive.target;
  if (target !== 'argument' && target !== 'receiver' && target !== 'annotation') return false;
  if (evaluation.details.length === 0) return false;
  return true;
}

function roleRank(role: CandidateRole, type: VulnerabilityType): number {
  const order: readonly CandidateRole[] =
    type === 'auth' || type === 'authz'
      ? ['security_boundary', 'source', 'sink', 'transform', 'unclassified']
      : ['sink', 'source', 'security_boundary', 'transform', 'unclassified'];
  return order.indexOf(role);
}

function candidateId(role: CandidateRole, file: string, line: number, column: number, fn: string): string {
  return `${role}:${file}:${line}:${column}:${fn}`;
}

export interface CollectOptions {
  readonly type: VulnerabilityType;
  readonly functionName?: string;
}

export interface CollectResult {
  readonly ordered: readonly SecurityCandidate[];
  readonly matchedBeforeFilter: number;
  readonly filteredConstant: number;
  readonly excludedDuplicates: number;
}

interface FunctionQuery {
  readonly methodName?: string;
  readonly classPart?: string;
  readonly raw: string;
}

function parseFunctionQuery(functionName: string): FunctionQuery {
  const trimmed = functionName.trim();
  const lastDot = trimmed.lastIndexOf('.');
  if (lastDot < 0) return { methodName: trimmed, raw: trimmed };
  return { methodName: trimmed.slice(lastDot + 1), classPart: trimmed.slice(0, lastDot), raw: trimmed };
}

function ruleMatchesClassPart(rule: NormalizedRule, classPart: string): boolean {
  const fqcn = fullyQualifiedName(rule);
  if (fqcn === undefined) return false;
  if (fqcn === classPart) return true;
  const simple = fqcn.slice(fqcn.lastIndexOf('.') + 1);
  return simple === classPart || fqcn.endsWith(`.${classPart}`);
}

function ruleMatchesFunctionQuery(rule: NormalizedRule, query: FunctionQuery): boolean {
  if (rule.match.kind === 'method_call') {
    if (rule.match.method !== query.methodName) return false;
    if (query.classPart !== undefined && !ruleMatchesClassPart(rule, query.classPart)) return false;
    return true;
  }
  if (rule.match.kind === 'constructor') {
    if (query.classPart === undefined) return query.methodName === rule.match.class;
    return ruleMatchesClassPart(rule, query.classPart);
  }
  return false;
}

function collectForRule(
  rule: NormalizedRule,
  index: RawIndexFile,
  out: MutableCandidate[],
  counters: { matched: number; filtered: number },
  mode: 'recall' | 'function',
  classifiedKeys: Set<string>,
): void {
  for (const file of index.files) {
    for (const site of file.sites) {
      const match = matchSite(site, file, rule);
      if (match === undefined) continue;
      // In function-name search, a receiver-type-unproven call is reported as `unclassified`
      // instead of being attributed to a well-known API.
      if (match.weak === true && mode === 'function') continue;
      counters.matched += 1;
      // A rule attribution (even when the candidate is then constant-filtered) means the call is
      // not "unclassified"; record it so function-name search does not double-report it.
      classifiedKeys.add(`${file.path}|${site.line}|${site.column}|${site.methodName ?? ''}`);
      if (shouldFilter(rule, site, file, match.confidence)) {
        counters.filtered += 1;
        continue;
      }
      out.push({
        role: rule.role,
        vulnerabilityTypes: new Set(rule.vulnerability_types),
        category: rule.category,
        file: file.path,
        line: site.line,
        column: site.column,
        ...(site.symbol !== undefined && { symbol: site.symbol }),
        function: functionText(site),
        ...(match.resolvedApi !== undefined && { resolvedApi: match.resolvedApi }),
        confidence: match.confidence,
        code: truncateCode(site.code),
        constantState: constantStateFor(rule, site, file),
        reason: rule.reason,
        ruleIds: [rule.id],
      });
    }
  }
}

function collectUnclassified(
  index: RawIndexFile,
  query: FunctionQuery,
  type: VulnerabilityType,
  out: MutableCandidate[],
  classifiedKeys: Set<string>,
): void {
  const methodName = query.methodName;
  if (methodName === undefined || methodName.length === 0) return;
  for (const file of index.files) {
    for (const site of file.sites) {
      if (site.kind === 'constructor') {
        const simple = (site.typeName ?? '').slice((site.typeName ?? '').lastIndexOf('.') + 1);
        const matches =
          query.classPart === undefined ? simple === methodName : (site.typeName ?? '').endsWith(query.classPart);
        if (!matches) continue;
      } else if (site.kind === 'call') {
        if (site.methodName !== methodName) continue;
        const key = `${file.path}|${site.line}|${site.column}|${site.methodName ?? ''}`;
        if (classifiedKeys.has(key)) continue;
      } else {
        continue;
      }
      out.push({
        role: 'unclassified',
        vulnerabilityTypes: new Set([type]),
        category: 'custom_function',
        file: file.path,
        line: site.line,
        column: site.column,
        ...(site.symbol !== undefined && { symbol: site.symbol }),
        function: functionText(site),
        confidence: 'name_only',
        code: truncateCode(site.code),
        constantState: 'unknown',
        reason: 'Same-named method call; not proven to be a known source/sink/boundary API',
        ruleIds: [],
      });
    }
  }
}

function mergeDuplicates(candidates: MutableCandidate[]): { merged: MutableCandidate[]; excluded: number } {
  const byKey = new Map<string, MutableCandidate>();
  let excluded = 0;
  for (const candidate of candidates) {
    const key = `${candidate.role}|${candidate.file}|${candidate.line}|${candidate.column}|${candidate.function}`;
    const existing = byKey.get(key);
    if (existing === undefined) {
      byKey.set(key, candidate);
      continue;
    }
    excluded += 1;
    for (const vt of candidate.vulnerabilityTypes) existing.vulnerabilityTypes.add(vt);
    for (const id of candidate.ruleIds) if (!existing.ruleIds.includes(id)) existing.ruleIds.push(id);
    if (CONFIDENCE_RANK[candidate.confidence] < CONFIDENCE_RANK[existing.confidence]) {
      existing.confidence = candidate.confidence;
      if (candidate.resolvedApi !== undefined) existing.resolvedApi = candidate.resolvedApi;
    }
    if (existing.constantState === 'unknown' && candidate.constantState !== 'unknown') {
      existing.constantState = candidate.constantState;
    }
  }
  return { merged: [...byKey.values()], excluded };
}

function orderGroup(list: MutableCandidate[], type: VulnerabilityType): MutableCandidate[] {
  const preference = CATEGORY_PREFERENCES[type];
  const groups = new Map<string, MutableCandidate[]>();
  for (const candidate of list) {
    const bucket = groups.get(candidate.category);
    if (bucket === undefined) groups.set(candidate.category, [candidate]);
    else bucket.push(candidate);
  }
  const categoryRank = (category: string): number => {
    const index = preference.indexOf(category);
    return index >= 0 ? index : preference.length;
  };
  const orderedGroups = [...groups.entries()].sort((a, b) => {
    const ra = categoryRank(a[0]);
    const rb = categoryRank(b[0]);
    if (ra !== rb) return ra - rb;
    return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
  });
  for (const [, bucket] of orderedGroups) {
    bucket.sort((a, b) => {
      const role = roleRank(a.role, type) - roleRank(b.role, type);
      if (role !== 0) return role;
      const confidence = CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence];
      if (confidence !== 0) return confidence;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      if (a.line !== b.line) return a.line - b.line;
      if (a.column !== b.column) return a.column - b.column;
      return a.function < b.function ? -1 : a.function > b.function ? 1 : 0;
    });
  }
  const result: MutableCandidate[] = [];
  let index = 0;
  let remaining = orderedGroups.reduce((sum, [, bucket]) => sum + bucket.length, 0);
  while (remaining > 0) {
    for (const [, bucket] of orderedGroups) {
      const item = bucket[index];
      if (item !== undefined) {
        result.push(item);
        remaining -= 1;
      }
    }
    index += 1;
  }
  return result;
}

function toCandidate(mutable: MutableCandidate): SecurityCandidate {
  const vulnerabilityTypes = [...mutable.vulnerabilityTypes].sort(
    (a, b) => SOURCE_ORDER.indexOf(a) - SOURCE_ORDER.indexOf(b),
  );
  return {
    id: candidateId(mutable.role, mutable.file, mutable.line, mutable.column, mutable.function),
    role: mutable.role,
    vulnerability_types: vulnerabilityTypes,
    category: mutable.category,
    file: mutable.file,
    line: mutable.line,
    column: mutable.column,
    ...(mutable.symbol !== undefined && { containing_symbol: mutable.symbol }),
    function: mutable.function,
    ...(mutable.resolvedApi !== undefined && { resolved_api: mutable.resolvedApi }),
    confidence: mutable.confidence,
    code: mutable.code,
    constant_state: mutable.constantState,
    reason: mutable.reason,
    rule_ids: [...mutable.ruleIds].sort(),
  };
}

/** Collect, filter, de-duplicate, and deterministically order every candidate for a query. */
export function collectCandidates(index: RawIndexFile, ruleSet: LoadedRuleSet, options: CollectOptions): CollectResult {
  const counters = { matched: 0, filtered: 0 };
  const matched: MutableCandidate[] = [];
  const classifiedKeys = new Set<string>();

  if (options.functionName !== undefined && options.functionName.trim().length > 0) {
    const query = parseFunctionQuery(options.functionName);
    const rules = ruleSet.rules.filter((rule) => ruleMatchesFunctionQuery(rule, query));
    for (const rule of rules) collectForRule(rule, index, matched, counters, 'function', classifiedKeys);
    collectUnclassified(index, query, options.type, matched, classifiedKeys);
  } else {
    for (const rule of ruleSet.rules) {
      if (!rule.vulnerability_types.includes(options.type)) continue;
      collectForRule(rule, index, matched, counters, 'recall', classifiedKeys);
    }
  }

  const { merged, excluded } = mergeDuplicates(matched);
  const classified = merged.filter((candidate) => candidate.role !== 'unclassified');
  const unclassified = merged.filter((candidate) => candidate.role === 'unclassified');
  const ordered = [...orderGroup(classified, options.type), ...orderGroup(unclassified, options.type)].map(toCandidate);

  return {
    ordered,
    matchedBeforeFilter: counters.matched,
    filteredConstant: counters.filtered,
    excludedDuplicates: excluded,
  };
}
