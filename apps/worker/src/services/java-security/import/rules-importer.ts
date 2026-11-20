// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Build-time, offline rule importer.
 *
 * Converts the clearly-static subset of upstream Source/Sink models (CodeQL `.model.yml`,
 * Tai-e/SecConfig signature lists, Find Security Bugs-style descriptor lists) into the normalized
 * rule schema. Anything it cannot convert is counted and exemplified in a report instead of being
 * guessed. Importers never run at scan time and never touch the network; the committed
 * `data/java-security-rules.json` is what the runtime loads.
 *
 * A missing or unfamiliar upstream license is surfaced in the report so a human can decide whether
 * the text may be redistributed; imported rules are only ever advisory until reviewed.
 */

import { createHash } from 'node:crypto';
import yaml from 'js-yaml';
import type {
  ConstantFilter,
  MatchKind,
  NormalizedRule,
  RuleOrigin,
  RuleRole,
  SensitiveTarget,
  VulnerabilityType,
} from '../types.js';
import { RULE_SCHEMA_VERSION } from '../types.js';

export type ImportFormat = 'codeql' | 'taie' | 'fsb';

export interface ImportInput {
  readonly path: string;
  readonly format: ImportFormat;
  readonly content: string;
  readonly repository: string;
  readonly commit: string;
  readonly license: string;
}

export interface ImportReport {
  readonly sourceFiles: number;
  readonly parsedRules: number;
  readonly unsupported: number;
  readonly duplicates: number;
  readonly conflicts: number;
  readonly byVulnerabilityType: Record<string, number>;
  readonly byRole: Record<string, number>;
  readonly unsupportedExamples: string[];
}

export interface ImportResult {
  readonly rules: NormalizedRule[];
  readonly report: ImportReport;
}

interface DraftRule {
  readonly id: string;
  readonly role: RuleRole;
  readonly category: string;
  readonly vulnerabilityTypes: VulnerabilityType[];
  readonly kind: MatchKind;
  readonly package?: string;
  readonly class?: string;
  readonly method?: string;
  readonly arity?: number;
  readonly sensitiveTarget: SensitiveTarget;
  readonly sensitiveIndexes?: number[];
  readonly constantFilter: ConstantFilter;
  readonly reason: string;
  readonly origin: RuleOrigin;
}

const FILTER_RANK: Readonly<Record<ConstantFilter, number>> = { never: 0, proven_constant_only: 1, format_aware: 2 };

function mostConservative(filters: readonly ConstantFilter[]): ConstantFilter {
  return filters.reduce(
    (acc, filter) => (FILTER_RANK[filter] < FILTER_RANK[acc] ? filter : acc),
    'format_aware' as ConstantFilter,
  );
}

function classifyKind(kind: string): { type: VulnerabilityType; category: string } {
  const lower = kind.toLowerCase();
  if (lower.includes('sql') || lower.includes('query')) return { type: 'injection', category: 'sql' };
  if (lower.includes('command') || lower.includes('exec')) return { type: 'injection', category: 'command' };
  if (lower.includes('path') || lower.includes('file') || lower.includes('traversal'))
    return { type: 'injection', category: 'path' };
  if (lower.includes('ldap') || lower.includes('jndi')) return { type: 'injection', category: 'ldap' };
  if (lower.includes('xss') || lower.includes('html') || lower.includes('render'))
    return { type: 'xss', category: 'xss_output' };
  if (
    lower.includes('url') ||
    lower.includes('ssrf') ||
    lower.includes('request') ||
    lower.includes('open') ||
    lower.includes('remote') ||
    lower.includes('network')
  ) {
    return { type: 'ssrf', category: 'url_request' };
  }
  if (lower.includes('authz') || lower.includes('permission') || lower.includes('access'))
    return { type: 'authz', category: 'authz_check' };
  if (lower.includes('auth')) return { type: 'auth', category: 'auth_source' };
  return { type: 'injection', category: 'other' };
}

function parseAccessPath(accessPath: string): { target: SensitiveTarget; indexes?: number[] } | undefined {
  const trimmed = accessPath.trim();
  // Only the simplest paths are convertible. `ReturnValue.Element`/`Argument[this].x` and other
  // composite access paths must stay unsupported rather than be downgraded to a wrong position.
  if (trimmed === 'ReturnValue') return { target: 'return' };
  if (trimmed === 'Argument[this]') return { target: 'receiver' };
  const match = /^Argument\[(\d+)\]$/.exec(trimmed);
  if (match && match[1] !== undefined) return { target: 'argument', indexes: [Number(match[1])] };
  return undefined;
}

function signatureArity(signature: string): number | undefined {
  const open = signature.indexOf('(');
  const close = signature.lastIndexOf(')');
  if (open < 0 || close < open) return undefined;
  const inner = signature.slice(open + 1, close).trim();
  if (inner.length === 0) return 0;
  let depth = 0;
  let count = 1;
  for (const char of inner) {
    if (char === '<') depth += 1;
    else if (char === '>') depth -= 1;
    else if (char === ',' && depth === 0) count += 1;
  }
  return count;
}

function ruleId(prefix: string, parts: readonly (string | number | undefined)[]): string {
  return `${prefix}:${createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 16)}`;
}

/** Parse CodeQL `.model.yml` sourceModel/sinkModel rows (the statically convertible subset). */
export function parseCodeqlModel(input: ImportInput): { drafts: DraftRule[]; unsupported: string[] } {
  const drafts: DraftRule[] = [];
  const unsupported: string[] = [];
  let doc: unknown;
  try {
    doc = yaml.load(input.content);
  } catch (error) {
    unsupported.push(`${input.path}: YAML parse failed (${error instanceof Error ? error.message : String(error)})`);
    return { drafts, unsupported };
  }
  const extensions = (doc as { extensions?: unknown })?.extensions;
  if (!Array.isArray(extensions)) return { drafts, unsupported };
  for (const extension of extensions) {
    const addsTo = (extension as { addsTo?: { extensible?: string } })?.addsTo;
    const extensible = addsTo?.extensible;
    const data = (extension as { data?: unknown })?.data;
    if (!Array.isArray(data)) continue;
    if (extensible !== 'sourceModel' && extensible !== 'sinkModel') {
      unsupported.push(`${input.path}: predicate ${String(extensible)} is outside the supported subset`);
      continue;
    }
    for (const row of data) {
      if (!Array.isArray(row) || row.length < 7) {
        unsupported.push(`${input.path}: malformed ${extensible} row ${JSON.stringify(row)}`);
        continue;
      }
      const [pkg, type, _subtypes, name, signature, _ext, access, kind] = row as (string | boolean)[];
      if (
        typeof pkg !== 'string' ||
        typeof type !== 'string' ||
        typeof name !== 'string' ||
        typeof access !== 'string'
      ) {
        unsupported.push(`${input.path}: row with non-string coordinates`);
        continue;
      }
      const parsed = parseAccessPath(access);
      if (parsed === undefined) {
        unsupported.push(`${input.path}: unsupported access path ${access}`);
        continue;
      }
      const classification = classifyKind(typeof kind === 'string' ? kind : 'injection');
      const role: RuleRole = extensible === 'sourceModel' ? 'source' : 'sink';
      const arity = typeof signature === 'string' ? signatureArity(signature) : undefined;
      drafts.push({
        id: ruleId('codeql', [role, pkg, type, name, typeof signature === 'string' ? signature : undefined, access]),
        role,
        category: classification.category,
        vulnerabilityTypes: [classification.type],
        kind: 'method_call',
        package: pkg,
        class: type,
        method: name,
        ...(arity !== undefined && arity > 0 && { arity }),
        sensitiveTarget: parsed.target,
        ...(parsed.indexes !== undefined && { sensitiveIndexes: parsed.indexes }),
        constantFilter: role === 'source' ? 'never' : parsed.target === 'argument' ? 'proven_constant_only' : 'never',
        reason: `Imported from ${input.repository} ${extensible} (${classification.category})`,
        origin: {
          repository: input.repository,
          commit: input.commit,
          file: input.path,
          original_rule: row.join(';'),
          license: input.license,
        },
      });
    }
  }
  return { drafts, unsupported };
}

/** Parse Tai-e / SecConfig `<class: ret method(args)>` entries with an optional `index:` line. */
export function parseTaiEModel(input: ImportInput): { drafts: DraftRule[]; unsupported: string[] } {
  const drafts: DraftRule[] = [];
  const unsupported: string[] = [];
  const lines = input.content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = (lines[i] ?? '').trim();
    if (!line || line.startsWith('#')) continue;
    const signature = /^<([^:>]+):\s*[^>]*?\b([A-Za-z_$][\w$]*)\(([^)]*)\)>$/.exec(line);
    if (!signature) continue;
    const fqcn = signature[1]?.trim() ?? '';
    const method = signature[2] ?? '';
    const params = signature[3] ?? '';
    const indexLine = (lines[i + 1] ?? '').trim();
    const indexMatch = /^index\s*:\s*(\d+|result|base)$/.exec(indexLine);
    const packageName = fqcn.includes('.') ? fqcn.slice(0, fqcn.lastIndexOf('.')) : undefined;
    const simpleClass = fqcn.slice(fqcn.lastIndexOf('.') + 1);
    const arity = params.trim().length === 0 ? 0 : params.split(',').length;
    let target: SensitiveTarget = 'argument';
    let indexes: number[] | undefined = [0];
    if (indexMatch?.[1] === 'result') target = 'return';
    else if (indexMatch?.[1] === 'base') target = 'receiver';
    else if (indexMatch?.[1] !== undefined) indexes = [Number(indexMatch[1])];
    else unsupported.push(`${input.path}: ${line} has no adjacent index directive; defaulted to argument 0`);
    drafts.push({
      id: ruleId('taie', [fqcn, method, arity, indexMatch?.[1] ?? '0']),
      role: target === 'return' ? 'source' : 'sink',
      category: 'other',
      vulnerabilityTypes: ['injection'],
      kind: 'method_call',
      ...(packageName !== undefined && { package: packageName }),
      class: simpleClass,
      method,
      arity,
      sensitiveTarget: target,
      ...(indexes !== undefined && { sensitiveIndexes: indexes }),
      constantFilter: target === 'argument' ? 'proven_constant_only' : 'never',
      reason: `Imported from ${input.repository} Tai-e-style taint rule`,
      origin: {
        repository: input.repository,
        commit: input.commit,
        file: input.path,
        original_rule: line,
        license: input.license,
      },
    });
  }
  return { drafts, unsupported };
}

/** Parse Find Security Bugs-style `fqcn.method(descriptor)` descriptor lists (best effort). */
export function parseDescriptorList(input: ImportInput): { drafts: DraftRule[]; unsupported: string[] } {
  const drafts: DraftRule[] = [];
  const unsupported: string[] = [];
  for (const rawLine of input.content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const match = /^([A-Za-z_$][\w$.]*)\.([A-Za-z_$][\w$]*)\((.*)\)/.exec(line);
    if (!match) {
      unsupported.push(`${input.path}: unrecognized descriptor line`);
      continue;
    }
    const fqcn = match[1] ?? '';
    const method = match[2] ?? '';
    const packageName = fqcn.includes('.') ? fqcn.slice(0, fqcn.lastIndexOf('.')) : undefined;
    const simpleClass = fqcn.slice(fqcn.lastIndexOf('.') + 1);
    drafts.push({
      id: ruleId('fsb', [fqcn, method]),
      role: 'sink',
      category: 'other',
      vulnerabilityTypes: ['injection'],
      kind: 'method_call',
      ...(packageName !== undefined && { package: packageName }),
      class: simpleClass,
      method,
      sensitiveTarget: 'argument',
      sensitiveIndexes: [0],
      constantFilter: 'proven_constant_only',
      reason: `Imported from ${input.repository} descriptor rule (argument index needs review)`,
      origin: {
        repository: input.repository,
        commit: input.commit,
        file: input.path,
        original_rule: line,
        license: input.license,
      },
    });
  }
  return { drafts, unsupported };
}

function draftToRule(draft: DraftRule): NormalizedRule {
  return {
    id: draft.id,
    language: 'java',
    role: draft.role,
    vulnerability_types: draft.vulnerabilityTypes,
    category: draft.category,
    match: {
      kind: draft.kind,
      ...(draft.package !== undefined && { package: draft.package }),
      ...(draft.class !== undefined && { class: draft.class }),
      ...(draft.method !== undefined && { method: draft.method }),
      ...(draft.arity !== undefined && { arity: draft.arity }),
    },
    sensitive: {
      target: draft.sensitiveTarget,
      ...(draft.sensitiveIndexes !== undefined && { indexes: draft.sensitiveIndexes }),
    },
    constant_filter: draft.constantFilter,
    reason: draft.reason,
    origin: [draft.origin],
  };
}

function draftKey(rule: NormalizedRule): string {
  return [
    rule.role,
    rule.category,
    rule.match.kind,
    rule.match.package ?? '',
    rule.match.class ?? '',
    rule.match.method ?? '',
    rule.match.arity ?? '',
    rule.sensitive.target,
    (rule.sensitive.indexes ?? []).join(','),
  ].join('|');
}

/** Import every input, merge duplicates conservatively, and produce a rule set plus a report. */
export function importRules(inputs: readonly ImportInput[]): ImportResult {
  const unsupportedExamples: string[] = [];
  let unsupported = 0;
  const byKey = new Map<string, NormalizedRule>();
  let duplicates = 0;
  let conflicts = 0;

  for (const input of inputs) {
    const parsed =
      input.format === 'codeql'
        ? parseCodeqlModel(input)
        : input.format === 'taie'
          ? parseTaiEModel(input)
          : parseDescriptorList(input);
    unsupported += parsed.unsupported.length;
    for (const example of parsed.unsupported) if (unsupportedExamples.length < 25) unsupportedExamples.push(example);
    for (const draft of parsed.drafts) {
      const rule = draftToRule(draft);
      const key = draftKey(rule);
      const existing = byKey.get(key);
      if (existing === undefined) {
        byKey.set(key, rule);
        continue;
      }
      duplicates += 1;
      if (existing.constant_filter !== rule.constant_filter) conflicts += 1;
      byKey.set(key, {
        ...existing,
        constant_filter: mostConservative([existing.constant_filter, rule.constant_filter]),
        origin: [...existing.origin, ...rule.origin],
      });
    }
  }

  const rules = [...byKey.values()];
  const byVulnerabilityType: Record<string, number> = {};
  const byRole: Record<string, number> = {};
  for (const rule of rules) {
    for (const type of rule.vulnerability_types) byVulnerabilityType[type] = (byVulnerabilityType[type] ?? 0) + 1;
    byRole[rule.role] = (byRole[rule.role] ?? 0) + 1;
  }

  return {
    rules,
    report: {
      sourceFiles: inputs.length,
      parsedRules: rules.length,
      unsupported,
      duplicates,
      conflicts,
      byVulnerabilityType,
      byRole,
      unsupportedExamples,
    },
  };
}

/** Merge imported rules with an existing committed rule set, preferring the existing rule on conflict. */
export function mergeRuleSets(
  existing: readonly NormalizedRule[],
  imported: readonly NormalizedRule[],
): NormalizedRule[] {
  const byKey = new Map<string, NormalizedRule>();
  for (const rule of existing) byKey.set(draftKey(rule), rule);
  for (const rule of imported) {
    const key = draftKey(rule);
    const current = byKey.get(key);
    if (current === undefined) byKey.set(key, rule);
    else byKey.set(key, { ...current, origin: [...current.origin, ...rule.origin] });
  }
  return [...byKey.values()];
}

export interface RuleSetArtifact {
  readonly schemaVersion: number;
  readonly ruleVersion: string;
  readonly generatedAt: string;
  readonly rules: NormalizedRule[];
}

export function buildRuleSetArtifact(
  rules: NormalizedRule[],
  ruleVersion: string,
  generatedAt: string,
): RuleSetArtifact {
  return { schemaVersion: RULE_SCHEMA_VERSION, ruleVersion, generatedAt, rules };
}
