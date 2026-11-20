// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * `findSecurityCandidates` — the read-only entry point shared by the tool wrapper and tests.
 *
 * The service never throws at the agent boundary: infrastructure faults (missing parser, unreadable
 * rules, timeout) become a structured `partial`/`unavailable` result with warnings so the surrounding
 * Pre-Recon/Recon workflow is never broken.
 */

import { createHash } from 'node:crypto';
import {
  getSecurityIndex,
  type IndexHandle,
  loadSecurityCandidatesConfig,
  type SecurityCandidatesConfig,
} from './cache.js';
import { collectCandidates } from './matcher.js';
import { loadRuleSet } from './rules.js';
import {
  type CandidateStats,
  type FindSecurityCandidatesInput,
  type FindSecurityCandidatesOutput,
  MAX_FUNCTION_NAME_LENGTH,
  type SecurityCandidate,
  SORT_VERSION,
} from './types.js';

interface CursorPayload {
  readonly v: number;
  readonly s: string;
  readonly r: string;
  readonly q: string;
  readonly o: number;
}

function encodeCursor(payload: CursorPayload): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

function decodeCursor(cursor: string): CursorPayload | undefined {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as unknown;
    if (typeof parsed !== 'object' || parsed === null) return undefined;
    const { v, s, r, q, o } = parsed as Record<string, unknown>;
    if (typeof v !== 'number' || typeof s !== 'string' || typeof r !== 'string' || typeof q !== 'string')
      return undefined;
    if (typeof o !== 'number' || !Number.isInteger(o) || o < 0) return undefined;
    return { v, s, r, q, o };
  } catch {
    return undefined;
  }
}

function queryHash(type: string, functionName: string | undefined): string {
  return createHash('sha256')
    .update(`${type}\u0000${functionName ?? ''}`)
    .digest('hex');
}

function clampLimit(limit: number, maxResults: number): number {
  const upper = Math.min(100, maxResults);
  if (!Number.isFinite(limit)) return upper;
  const normalized = Math.trunc(limit);
  if (normalized < 1) return 1;
  return Math.min(normalized, upper);
}

function emptyStats(handle: IndexHandle | undefined, timeout = false): CandidateStats {
  return {
    matched_before_filter: 0,
    filtered_constant: 0,
    excluded_duplicates: 0,
    files_scanned: handle?.stats.filesScanned ?? 0,
    files_skipped: handle?.stats.filesSkipped ?? 0,
    parse_errors: handle?.stats.parseErrors ?? 0,
    timeout: handle?.stats.timeout ?? timeout,
  };
}

export interface FindSecurityCandidatesOptions {
  readonly sourceDir: string;
  readonly config?: SecurityCandidatesConfig;
}

function unavailable(
  input: FindSecurityCandidatesInput,
  limit: number,
  warnings: readonly string[],
): FindSecurityCandidatesOutput {
  return {
    status: 'unavailable',
    vulnerability_type: input.vulnerability_type,
    requested: limit,
    returned: 0,
    candidates: [],
    has_more: false,
    stats: emptyStats(undefined),
    warnings: [...warnings],
  };
}

/** Resolve candidate locations for a single query, with stable cursor pagination. */
export async function findSecurityCandidates(
  input: FindSecurityCandidatesInput,
  options: FindSecurityCandidatesOptions,
): Promise<FindSecurityCandidatesOutput> {
  const config = options.config ?? loadSecurityCandidatesConfig();
  const warnings: string[] = [];
  const limit = clampLimit(input.limit, config.maxResults);

  let functionName = input.function_name;
  if (functionName !== undefined && functionName.length > MAX_FUNCTION_NAME_LENGTH) {
    functionName = functionName.slice(0, MAX_FUNCTION_NAME_LENGTH);
    warnings.push(`function_name truncated to ${MAX_FUNCTION_NAME_LENGTH} characters`);
  }

  if (!config.enabled) {
    return unavailable(input, limit, ['security candidate search is disabled']);
  }

  let handle: IndexHandle;
  let ruleHash: string;
  try {
    const ruleSet = loadRuleSet();
    ruleHash = ruleSet.hash;
    handle = await getSecurityIndex(options.sourceDir, config);
  } catch (error) {
    return unavailable(input, limit, [
      `security candidate index unavailable: ${error instanceof Error ? error.message : String(error)}`,
    ]);
  }
  warnings.push(...handle.warnings);

  const collect = collectCandidates(handle.index, loadRuleSet(), {
    type: input.vulnerability_type,
    ...(functionName !== undefined && { functionName }),
  });
  const ordered: readonly SecurityCandidate[] = collect.ordered;
  const snapshotId = handle.index.snapshotId;
  const qHash = queryHash(input.vulnerability_type, functionName);

  const baseStats: CandidateStats = {
    matched_before_filter: collect.matchedBeforeFilter,
    filtered_constant: collect.filteredConstant,
    excluded_duplicates: collect.excludedDuplicates,
    files_scanned: handle.stats.filesScanned,
    files_skipped: handle.stats.filesSkipped,
    parse_errors: handle.stats.parseErrors,
    timeout: handle.stats.timeout,
  };

  let offset = 0;
  if (input.cursor !== undefined) {
    const decoded = decodeCursor(input.cursor);
    if (
      decoded === undefined ||
      decoded.v !== SORT_VERSION ||
      decoded.s !== snapshotId ||
      decoded.r !== ruleHash ||
      decoded.q !== qHash
    ) {
      return {
        status: 'invalid_cursor',
        vulnerability_type: input.vulnerability_type,
        requested: limit,
        returned: 0,
        snapshot_id: snapshotId,
        candidates: [],
        has_more: false,
        stats: baseStats,
        warnings: [...warnings, 'cursor does not match the current index snapshot, rule version, or query'],
      };
    }
    offset = decoded.o;
  }

  const page = ordered.slice(offset, offset + limit);
  const hasMore = offset + limit < ordered.length;
  const nextCursor = hasMore
    ? encodeCursor({ v: SORT_VERSION, s: snapshotId, r: ruleHash, q: qHash, o: offset + limit })
    : undefined;

  // A truncated scan or any unparsable file means coverage is incomplete, so the result is
  // 'partial' rather than a clean 'complete'; the caller still gets the candidates found so far.
  const status = handle.stats.timeout || handle.stats.parseErrors > 0 ? 'partial' : 'complete';
  return {
    status,
    vulnerability_type: input.vulnerability_type,
    requested: limit,
    returned: page.length,
    snapshot_id: snapshotId,
    candidates: page,
    ...(nextCursor !== undefined && { next_cursor: nextCursor }),
    has_more: hasMore,
    stats: baseStats,
    warnings,
  };
}
