// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shared types for the AST-based structural clone retrieval (Explore v3).
 *
 * The production Explore stage used to retrieve candidates from normalized-token n-grams
 * (`services/explore-clone-search.ts`, `normalized_token_clone_v1`). This module describes the
 * replacement: a Sink-anchored AST Forest, structural features, and an ordered tree/forest match.
 * The old token search is intentionally kept as an offline baseline and can still be selected.
 */

import type { CloneSearchSeed } from '../explore-clone-search.js';

/** A recorded, record-verified sink location to search from. Structurally identical to v2. */
export type AstCloneSearchSeed = CloneSearchSeed;

/** Languages this pass parses with Tree-sitter. A seed is only compared with its own language. */
export type AstLanguage = 'javascript' | 'typescript' | 'tsx' | 'java';

/**
 * Language-independent node categories. Identifiers and literals are collapsed (`IDENTIFIER`,
 * `LITERAL`) but `CALL`, `IF`, `RETURN`, `AWAIT`, operators, accesses and the argument count are
 * preserved so structurally different code never looks identical.
 */
export type AstNodeCategory =
  | 'FOREST'
  | 'BLOCK'
  | 'DECLARATION'
  | 'ASSIGNMENT'
  | 'CALL'
  | 'AWAIT'
  | 'RETURN'
  | 'IF'
  | 'LOOP'
  | 'TRY'
  | 'BINARY_OP'
  | 'UNARY_OP'
  | 'MEMBER_ACCESS'
  | 'INDEX_ACCESS'
  | 'LAMBDA'
  | 'IDENTIFIER'
  | 'LITERAL'
  | 'OTHER';

/** One node of the normalized AST. `children` order is significant and never reordered. */
export interface NormalizedAstNode {
  /** Stable id within the single parse of one file, assigned in pre-order. */
  readonly id: number;
  readonly type: AstNodeCategory;
  /** Grammar field of this node within its parent (`condition`, `arguments`, `body`, ...). */
  readonly field?: string | undefined;
  /**
   * Bounded structural detail: operator text, call arity, declaration kind. Never an identifier
   * or literal value, so a rename (Type-2) does not change structural features.
   */
  readonly detail?: string | undefined;
  /** Soft API label (callee name). Used only as a low-weight feature, never a hard condition. */
  readonly softLabel?: string | undefined;
  parentId: number;
  readonly children: NormalizedAstNode[];
  readonly startByte: number;
  readonly endByte: number;
  /** One-based inclusive line range (Tree-sitter rows are zero-based and converted here). */
  readonly startLine: number;
  readonly endLine: number;
}

export interface AstContextEntry {
  readonly type: AstNodeCategory;
  readonly field?: string | undefined;
}

/** Sink-anchored local AST forest: the anchor statement subtree plus nearby siblings/context. */
export interface AstForest {
  readonly language: AstLanguage;
  readonly file: string;
  /** Synthetic FOREST root; it has no source range of its own. */
  readonly root: NormalizedAstNode;
  readonly nodes: readonly NormalizedAstNode[];
  readonly anchorNodeId: number;
  readonly anchorStatementId: number;
  readonly anchorLine: number;
  /** Ancestor control context from the anchor statement upward (IF/LOOP/TRY/LAMBDA/BLOCK). */
  readonly contextPath: readonly AstContextEntry[];
  readonly startLine: number;
  readonly endLine: number;
  readonly nodeCount: number;
}

export interface AstFeatureWeights {
  readonly node: number;
  readonly edge: number;
  readonly shapeDepth2: number;
  readonly shapeDepth3: number;
  readonly context: number;
  readonly api: number;
}

/** Tunable retrieval, indexing and matching parameters. Defaults favour recall, then structure. */
export const AST_SEARCH_DEFAULTS = Object.freeze({
  /** Maximum number of seeds searched in one pass. */
  maxSeeds: 30,
  /** Repository scan caps. Exceeding any marks the run as truncated. */
  maxFiles: 5_000,
  maxFileBytes: 1_000_000,
  maxIndexedForests: 100_000,
  /** Maximum nodes kept in one seed/candidate forest (whole statements are never cut). */
  maxForestNodes: 180,
  /** Forests below this many nodes are low-confidence short samples. */
  minForestNodes: 12,
  /** Inverted-index candidates promoted to the expensive ordered-tree match, per seed. */
  maxCandidateForestsPerSeed: 100,
  /** Structure-matched hits kept per seed. */
  maxPreciseMatchesPerSeed: 10,
  maxMatchesPerSeed: 10,
  maxTotalMatches: 100,
  /** Distinct anchor statements searched per seed line (one line can hold several calls). */
  maxAnchorAlternativesPerSeed: 3,
  /** Sibling statements kept on each side of the anchor statement. */
  siblingRadius: 2,
  /** Semantic ancestor levels retained in `contextPath`. */
  maxAncestorDepth: 3,
  /** Ordered-tree DP budget guards. */
  maxMatcherCellsPerPair: 200_000,
  maxMatchOperationsPerSeed: 10_000_000,
  /** Minimum weighted-Dice retrieval score admitted to the ordered-tree match. */
  minRetrievalScore: 0.25,
  /** Minimum ordered-tree similarity for a reported match. */
  minTreeSimilarity: 0.5,
  /** Maximum candidates indexed per file. */
  maxCandidatesPerFile: 400,
  /** Excerpt length stored with each match. */
  maxExcerptLength: 800,
  /** Base feature weights; multiplied by inverse document frequency at index time. */
  baseWeights: Object.freeze({ node: 1, edge: 2, shapeDepth2: 3, shapeDepth3: 4, context: 2, api: 1 }),
});

export type AstCloneSearchOptions = Omit<typeof AST_SEARCH_DEFAULTS, 'baseWeights'> & {
  readonly baseWeights: AstFeatureWeights;
};

export type AstSeedSkipReason =
  | 'invalid_seed_line'
  | 'unsupported_language'
  | 'seed_file_missing'
  | 'seed_path_outside_repository'
  | 'seed_path_not_regular_file'
  | 'seed_unreadable'
  | 'seed_too_short'
  | 'parse_error'
  | 'anchor_not_found'
  | 'anchor_ambiguous'
  | 'forest_too_small'
  | 'no_structural_features'
  | 'matcher_budget_exceeded'
  | 'parser_not_available'
  | 'seed_limit';

/** Explanation of how one candidate matched, mirrored into `ast_evidence`. */
export interface AstMatchEvidence {
  readonly retrieval_score: number;
  readonly tree_similarity: number;
  readonly anchor_confidence: number;
  readonly seed_nodes: number;
  readonly candidate_nodes: number;
  readonly mapped_nodes: number;
  readonly inserted_subtrees: number;
  readonly deleted_subtrees: number;
  readonly control_context_changed: boolean;
  readonly anchor_mapped: boolean;
}

export interface AstCloneMatch {
  readonly finding_id: string;
  readonly vulnerability_class: string;
  readonly seed_file: string;
  readonly seed_line: number;
  readonly match_file: string;
  readonly match_line: number;
  readonly candidate_start_line: number;
  readonly candidate_end_line: number;
  readonly score: number;
  readonly excerpt: string;
  readonly ast_evidence: AstMatchEvidence;
}

export interface AstSeedRecord {
  readonly finding_id: string;
  readonly vulnerability_class: string;
  readonly seed_file: string;
  readonly seed_line: number;
  readonly language?: AstLanguage | undefined;
  readonly status: 'eligible' | 'skipped';
  readonly reason?: AstSeedSkipReason | undefined;
  readonly anchor_line: number;
  readonly anchor_candidates: number;
  readonly node_count: number;
  readonly context_depth: number;
  readonly retrieval_candidates: number;
  readonly reranked_candidates: number;
  readonly matched: number;
}

/** Payload of `explore_search_results.json` (schema v3); `matches` is the Expansion entry point. */
export interface AstSearchResult {
  readonly schema_version: 3;
  readonly algorithm: 'ast_structural_clone_v1';
  readonly matches: AstCloneMatch[];
  readonly skipped_seeds: AstSeedRecord[];
  readonly truncated: boolean;
  readonly statistics: {
    readonly seed_count: number;
    readonly eligible_seed_count: number;
    readonly candidate_count: number;
    readonly parse_failed_files: number;
    readonly indexed_forests: number;
    readonly retrieval_candidates: number;
    readonly reranked_candidates: number;
    readonly unmapped_anchors: number;
    readonly ambiguous_anchors: number;
    readonly matcher_budget_exceeded: number;
    readonly parser_language_unsupported: number;
  };
}

export interface AstSeedsDocument {
  readonly schema_version: 3;
  readonly algorithm: 'ast_structural_clone_v1';
  readonly seeds: AstSeedRecord[];
  readonly truncated: boolean;
}

export interface AstCoverageDocument {
  readonly schema_version: 3;
  readonly algorithm: 'ast_structural_clone_v1';
  readonly summary: {
    readonly seeds_total: number;
    readonly seeds_eligible: number;
    readonly seeds_skipped: number;
    readonly indexed_files: number;
    readonly indexed_forests: number;
    readonly parse_failed_files: number;
    readonly retrieval_candidates: number;
    readonly reranked_candidates: number;
    readonly unmapped_anchors: number;
    readonly ambiguous_anchors: number;
    readonly matcher_budget_exceeded: number;
    readonly parser_language_unsupported: number;
    readonly matched: number;
    readonly truncated: boolean;
  };
  readonly skip_reasons: Record<string, number>;
  readonly seeds: AstSeedRecord[];
}

export interface AstCloneSearchOutcome {
  readonly result: AstSearchResult;
  readonly seeds: AstSeedsDocument;
  readonly coverage: AstCoverageDocument;
}
