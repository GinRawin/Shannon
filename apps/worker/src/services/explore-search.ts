// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Explore / Expansion location admission.
 *
 * The Explore stage now produces deterministic Type-2/Type-3 clone candidates
 * (`services/explore-clone-search.ts`). Every candidate carries an exact `match_file` + `match_line`
 * pointing at the candidate statement, and these helpers are the single admission rule the
 * expansion pass uses: a submitted `sink` location must cover one of the Explore hits exactly.
 * A matching file name alone is never enough.
 */

export interface ExploreSearchLocation {
  readonly match_file: string;
  readonly match_line: number;
}

interface CandidateCodeLocation {
  file?: unknown;
  start_line?: unknown;
  end_line?: unknown;
  role?: unknown;
}

/** True when a structured location covers an exact deterministic Explore match. */
export function locationMatchesExploreSearch(
  location: CandidateCodeLocation,
  matches: readonly ExploreSearchLocation[],
): boolean {
  if (
    typeof location.file !== 'string' ||
    !Number.isInteger(location.start_line) ||
    (location.start_line as number) < 1
  )
    return false;
  const startLine = location.start_line as number;
  const endLine = location.end_line === undefined ? startLine : location.end_line;
  if (!Number.isInteger(endLine) || (endLine as number) < startLine) return false;
  return matches.some(
    (match) =>
      match.match_file === location.file && match.match_line >= startLine && match.match_line <= (endLine as number),
  );
}

/** Independent candidates must identify an Explore hit as one of their sink locations. */
export function candidateMatchesExploreSearch(
  candidate: Record<string, unknown>,
  matches: readonly ExploreSearchLocation[],
): boolean {
  return (
    Array.isArray(candidate.code_locations) &&
    candidate.code_locations.some(
      (location) =>
        !!location &&
        typeof location === 'object' &&
        (location as CandidateCodeLocation).role === 'sink' &&
        locationMatchesExploreSearch(location as CandidateCodeLocation, matches),
    )
  );
}
