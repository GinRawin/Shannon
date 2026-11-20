// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Rule loading and indexing for the Java source/sink candidate retriever.
 *
 * The rule set ships as a committed JSON file (`data/java-security-rules.json`) and is loaded
 * offline; the module never clones a repository and never reaches the network at scan time. Each
 * rule keeps its `origin` so an upgrade can be audited. A malformed or empty rule file degrades to
 * a typed unavailable state rather than silently reporting a clean scan.
 */

import { createHash } from 'node:crypto';
import rulesJson from './data/java-security-rules.json' with { type: 'json' };
import type { NormalizedRule, RuleSetFile, VulnerabilityType } from './types.js';
import { RULE_SCHEMA_VERSION } from './types.js';

export interface LoadedRuleSet {
  readonly version: string;
  readonly rules: readonly NormalizedRule[];
  readonly hash: string;
  /** method_call rules keyed by method name. */
  readonly byMethodName: ReadonlyMap<string, readonly NormalizedRule[]>;
  /** constructor rules keyed by simple class name. */
  readonly byConstructorClass: ReadonlyMap<string, readonly NormalizedRule[]>;
  /** annotation rules keyed by annotation simple name. */
  readonly byAnnotationName: ReadonlyMap<string, readonly NormalizedRule[]>;
  /** Rule classes seen, used to decide whether a function_name is a known API. */
  readonly knownMethodNames: ReadonlySet<string>;
}

export class RuleSetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuleSetError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** A conservative structural validation; unknown extra fields are ignored, missing ones fail. */
function validateRule(raw: unknown, index: number): NormalizedRule {
  if (!isRecord(raw)) throw new RuleSetError(`rule ${index} is not an object`);
  const { id, vulnerability_types, category, match, sensitive, constant_filter, reason } = raw;
  if (typeof id !== 'string' || id.length === 0) throw new RuleSetError(`rule ${index} is missing id`);
  if (typeof category !== 'string') throw new RuleSetError(`rule ${id} is missing category`);
  if (typeof reason !== 'string') throw new RuleSetError(`rule ${id} is missing reason`);
  if (!Array.isArray(vulnerability_types) || vulnerability_types.length === 0) {
    throw new RuleSetError(`rule ${id} is missing vulnerability_types`);
  }
  if (!isRecord(match) || typeof match.kind !== 'string') throw new RuleSetError(`rule ${id} has no match.kind`);
  if (!isRecord(sensitive) || typeof sensitive.target !== 'string') {
    throw new RuleSetError(`rule ${id} has no sensitive.target`);
  }
  if (constant_filter !== 'never' && constant_filter !== 'proven_constant_only' && constant_filter !== 'format_aware') {
    throw new RuleSetError(`rule ${id} has an unknown constant_filter`);
  }
  return raw as unknown as NormalizedRule;
}

function computeHash(file: RuleSetFile): string {
  // Hash the loaded structure deterministically (property order follows the committed file).
  return createHash('sha256').update(JSON.stringify(file)).digest('hex');
}

let cached: LoadedRuleSet | undefined;
let loadFailure: RuleSetError | undefined;

function build(file: RuleSetFile): LoadedRuleSet {
  if (file.schemaVersion !== RULE_SCHEMA_VERSION) {
    throw new RuleSetError(`rule schema version ${file.schemaVersion} != supported ${RULE_SCHEMA_VERSION}`);
  }
  if (!Array.isArray(file.rules) || file.rules.length === 0) throw new RuleSetError('rule set contains no rules');
  const rules = file.rules.map((r, i) => validateRule(r, i));

  const byMethodName = new Map<string, NormalizedRule[]>();
  const byConstructorClass = new Map<string, NormalizedRule[]>();
  const byAnnotationName = new Map<string, NormalizedRule[]>();
  const knownMethodNames = new Set<string>();
  const push = (map: Map<string, NormalizedRule[]>, key: string, rule: NormalizedRule): void => {
    const existing = map.get(key);
    if (existing === undefined) map.set(key, [rule]);
    else existing.push(rule);
  };

  for (const rule of rules) {
    const { kind, method, class: cls, annotation_name } = rule.match;
    if (kind === 'method_call' && method !== undefined) {
      push(byMethodName, method, rule);
      knownMethodNames.add(method);
    }
    if (kind === 'constructor' && cls !== undefined) {
      push(byConstructorClass, cls, rule);
    }
    if (kind === 'annotation' && annotation_name !== undefined) {
      push(byAnnotationName, annotation_name, rule);
    }
  }

  return {
    version: file.ruleVersion,
    rules,
    hash: computeHash(file),
    byMethodName,
    byConstructorClass,
    byAnnotationName,
    knownMethodNames,
  };
}

/** Load and index the bundled rule set. The result is cached for the process lifetime. */
export function loadRuleSet(): LoadedRuleSet {
  if (cached !== undefined) return cached;
  if (loadFailure !== undefined) throw loadFailure;
  try {
    cached = build(rulesJson as unknown as RuleSetFile);
    return cached;
  } catch (error) {
    loadFailure = error instanceof RuleSetError ? error : new RuleSetError(String(error));
    throw loadFailure;
  }
}

/** Rules whose vulnerability_types include the requested type. */
export function rulesForType(set: LoadedRuleSet, type: VulnerabilityType): readonly NormalizedRule[] {
  return set.rules.filter((rule) => rule.vulnerability_types.includes(type));
}

export function fullyQualifiedName(rule: NormalizedRule): string | undefined {
  const { package: pkg, class: cls } = rule.match;
  if (cls === undefined) return undefined;
  return pkg !== undefined && pkg.length > 0 ? `${pkg}.${cls}` : cls;
}
