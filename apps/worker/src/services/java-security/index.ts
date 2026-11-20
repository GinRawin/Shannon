// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/** Public surface of the Java source/sink candidate retriever. */

export {
  getSecurityIndex,
  type IndexHandle,
  type IndexStats,
  loadSecurityCandidatesConfig,
  resetSecurityIndexCache,
  type SecurityCandidatesConfig,
} from './cache.js';
export { collectCandidates } from './matcher.js';
export { fullyQualifiedName, type LoadedRuleSet, loadRuleSet, RuleSetError, rulesForType } from './rules.js';
export { type FindSecurityCandidatesOptions, findSecurityCandidates } from './service.js';
export * from './types.js';
