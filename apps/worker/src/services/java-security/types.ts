// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shared types for the Java source/sink candidate retriever.
 *
 * This is one read-only retrieval aid for the Pre-Recon/Recon agents. It reports *locations* an
 * agent can trace by hand; it never claims a confirmed vulnerability, and it never performs
 * whole-program taint analysis. The public contract (input, candidate, output) is deliberately
 * stable: an agent may page through it and re-query it, so field names and `status` values are
 * part of the interface, not an internal detail.
 */

/** The five vulnerability classes used across Shannon's pipeline. */
export const VULNERABILITY_TYPES = ['injection', 'xss', 'ssrf', 'auth', 'authz'] as const;
export type VulnerabilityType = (typeof VULNERABILITY_TYPES)[number];

/** Bumped whenever the persisted raw index layout changes; part of the cache key. */
export const INDEX_SCHEMA_VERSION = 1;
/** Bumped whenever the deterministic sort/pagination layout changes. */
export const SORT_VERSION = 1;
/** Bumped whenever the rule schema changes; part of the cache key. */
export const RULE_SCHEMA_VERSION = 1;

export type CandidateRole = 'source' | 'sink' | 'transform' | 'security_boundary' | 'unclassified';
export type RuleRole = 'source' | 'sink' | 'transform' | 'security_boundary';
export type MatchConfidence = 'exact_signature' | 'type_inferred' | 'name_only' | 'structural';
export type ConstState = 'constant' | 'dynamic' | 'unknown' | 'not_applicable';
export type ConstantFilter = 'never' | 'proven_constant_only' | 'format_aware';
export type MatchKind = 'method_call' | 'constructor' | 'annotation' | 'xml_mapper';
export type SensitiveTarget = 'argument' | 'receiver' | 'return' | 'parameter' | 'annotation' | 'xml_body' | 'none';

export interface RuleOrigin {
  readonly repository: string;
  readonly commit: string;
  readonly file: string;
  readonly original_rule: string;
  readonly license: string;
}

export interface RuleMatch {
  readonly kind: MatchKind;
  /** Fully-qualified or partially-qualified package, e.g. `java.sql`. */
  readonly package?: string;
  /** Class (or nested class path) relative to the package, e.g. `Statement`. */
  readonly class?: string;
  /** Method name for `method_call` rules. */
  readonly method?: string;
  /** Exact argument count for overload precision; omitted means arity-agnostic. */
  readonly arity?: number;
  /** Source signature when known; a missing signature can never yield `exact_signature`. */
  readonly signature?: string;
  /** When true and the AST cannot prove the subtype relation, matching degrades to weak. */
  readonly match_subtypes?: boolean;
  /** Annotation simple name for `annotation` rules, e.g. `RequestMapping`. */
  readonly annotation_name?: string;
}

export interface RuleSensitive {
  readonly target: SensitiveTarget;
  /** 0-based AST argument indexes. Omitted/empty for `argument` means "every argument". */
  readonly indexes?: readonly number[];
}

export interface NormalizedRule {
  readonly id: string;
  readonly language: 'java';
  readonly role: RuleRole;
  readonly vulnerability_types: readonly VulnerabilityType[];
  readonly category: string;
  readonly match: RuleMatch;
  readonly sensitive: RuleSensitive;
  readonly constant_filter: ConstantFilter;
  readonly reason: string;
  readonly origin: readonly RuleOrigin[];
}

export interface RuleSetFile {
  readonly schemaVersion: number;
  readonly ruleVersion: string;
  readonly generatedAt: string;
  readonly rules: readonly NormalizedRule[];
}

/** A resolved constant/dynamic/unknown evaluation of one sensitive expression. */
export type ConstEval =
  | { readonly state: 'constant'; readonly value?: string | number | boolean | null }
  | { readonly state: 'dynamic' }
  | { readonly state: 'unknown'; readonly reason: string };

/** Bounded, serializable expression fragment retained in the raw index for later evaluation. */
export type ExprNode =
  | { readonly k: 'literal'; readonly type: 'string' | 'number' | 'bool' | 'char' | 'null'; readonly value: string }
  | { readonly k: 'ident'; readonly name: string }
  | { readonly k: 'member'; readonly target: ExprNode | null; readonly name: string; readonly text: string }
  | { readonly k: 'call'; readonly receiver: string | null; readonly name: string; readonly args: readonly ExprNode[] }
  | { readonly k: 'new'; readonly typeName: string; readonly args: readonly ExprNode[] }
  | { readonly k: 'binary'; readonly op: string; readonly left: ExprNode; readonly right: ExprNode }
  | { readonly k: 'paren'; readonly inner: ExprNode }
  | { readonly k: 'array'; readonly elements: readonly ExprNode[] }
  | { readonly k: 'other'; readonly text: string };

export interface RawArg {
  readonly expr: ExprNode;
  readonly line: number;
  readonly column: number;
  readonly text: string;
}

export interface RawSite {
  readonly kind: 'call' | 'constructor' | 'annotation' | 'method_declaration';
  readonly line: number;
  readonly column: number;
  readonly methodName?: string;
  readonly typeName?: string;
  readonly annotationName?: string;
  /** Raw receiver expression text, e.g. `stmt`, `Runtime.getRuntime()`, `new ProcessBuilder(...)`. */
  readonly receiverText?: string;
  /** Root simple identifier of the receiver when it is a plain name or a static qualifier. */
  readonly receiverRoot?: string;
  /** Shape of the receiver expression; drives how type information is resolved. */
  readonly receiverShape?: 'identifier' | 'static_call' | 'chain' | 'new' | 'none';
  readonly argCount: number;
  readonly args: readonly RawArg[];
  readonly code: string;
  readonly symbol?: string;
}

/** A simple, single-assignment local usable for bounded constant folding. */
export interface LocalDef {
  readonly line: number;
  readonly declaredType?: string;
  readonly expr?: ExprNode;
  /** True when the name is assigned more than once, or assigned anywhere but its declaration. */
  readonly reassigned: boolean;
  /** True when any assignment sits inside a branch/loop/try block. */
  readonly inBranch: boolean;
  /** True for a declared method parameter: a runtime input, never a foldable constant. */
  readonly isParameter?: boolean;
}

export interface FileIndexEntry {
  /** Source-root-relative POSIX path. Absolute paths are never persisted. */
  readonly path: string;
  readonly sha256: string;
  /** simple class name -> fully qualified name, from import declarations. */
  readonly imports: Readonly<Record<string, string>>;
  /** field name -> declared type text. */
  readonly fields: Readonly<Record<string, string>>;
  /** containing symbol -> local name -> definition. */
  readonly locals: Readonly<Record<string, Readonly<Record<string, LocalDef>>>>;
  /** Each entry is one candidate anchor; ordering is by line then column. */
  readonly sites: readonly RawSite[];
  readonly parseError: boolean;
}

export interface RawIndexFile {
  readonly schemaVersion: number;
  readonly indexSchemaVersion: number;
  readonly ruleVersionHash: string;
  readonly scanParamsHash: string;
  readonly snapshotId: string;
  readonly filesScanned: number;
  readonly filesSkipped: number;
  readonly parseErrors: number;
  readonly truncated: boolean;
  readonly files: readonly FileIndexEntry[];
}

export interface SecurityCandidate {
  readonly id: string;
  readonly role: CandidateRole;
  readonly vulnerability_types: readonly VulnerabilityType[];
  readonly category: string;
  readonly file: string;
  readonly line: number;
  readonly column?: number;
  readonly containing_symbol?: string;
  readonly function: string;
  readonly resolved_api?: string;
  readonly confidence: MatchConfidence;
  readonly code: string;
  readonly constant_state: ConstState;
  readonly reason: string;
  readonly rule_ids: readonly string[];
}

export interface CandidateStats {
  readonly matched_before_filter: number;
  readonly filtered_constant: number;
  readonly excluded_duplicates: number;
  readonly files_scanned: number;
  readonly files_skipped: number;
  readonly parse_errors: number;
  readonly timeout: boolean;
}

export type FindStatus = 'complete' | 'partial' | 'unavailable' | 'invalid_cursor';

export interface FindSecurityCandidatesOutput {
  readonly status: FindStatus;
  readonly vulnerability_type: VulnerabilityType;
  readonly requested: number;
  readonly returned: number;
  readonly snapshot_id?: string;
  readonly candidates: readonly SecurityCandidate[];
  readonly next_cursor?: string;
  readonly has_more: boolean;
  readonly stats: CandidateStats;
  readonly warnings: readonly string[];
}

export interface FindSecurityCandidatesInput {
  readonly vulnerability_type: VulnerabilityType;
  readonly limit: number;
  readonly function_name?: string;
  readonly cursor?: string;
}

export function isVulnerabilityType(value: unknown): value is VulnerabilityType {
  return typeof value === 'string' && (VULNERABILITY_TYPES as readonly string[]).includes(value);
}

export const MAX_FUNCTION_NAME_LENGTH = 256;
export const MAX_CANDIDATE_CODE_LENGTH = 240;
