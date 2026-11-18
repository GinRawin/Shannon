// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Single public entry point for the Explore v3 AST structural clone retrieval.
 *
 * The implementation lives in `services/explore-ast/`; this module is the stable import path for the
 * Explore activity and for offline benchmarks, mirroring `explore-clone-search.ts` for v2.
 */

export { AstParserUnavailableError, astLanguageForPath } from './explore-ast/parser.js';
export { searchAstCloneCandidates } from './explore-ast/search.js';
export type {
  AstCloneMatch,
  AstCloneSearchOptions,
  AstCloneSearchOutcome,
  AstCloneSearchSeed,
  AstCoverageDocument,
  AstFeatureWeights,
  AstForest,
  AstLanguage,
  AstMatchEvidence,
  AstNodeCategory,
  AstSearchResult,
  AstSeedRecord,
  AstSeedSkipReason,
  AstSeedsDocument,
  NormalizedAstNode,
} from './explore-ast/types.js';
export { AST_SEARCH_DEFAULTS } from './explore-ast/types.js';
export { candidateMatchesExploreSearch, locationMatchesExploreSearch } from './explore-search.js';
