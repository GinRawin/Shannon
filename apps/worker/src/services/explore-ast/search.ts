// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Explore v3 entry point: Sink-anchored AST structural clone retrieval.
 *
 * Record-verified sink lines are turned into AST anchors, expanded into local statement forests,
 * recalled through a structural-feature inverted index, and finally aligned with an ordered
 * tree/forest match that maps the seed anchor onto an exact candidate statement. The module is free
 * of Agent/Temporal dependencies, never calls an LLM, and only reports *similar code*: the class
 * expansion pass still decides whether a candidate is vulnerable.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { extractFeatures } from './features.js';
import { buildForest, compactForest, findAnchorNodes, primaryAnchor, statementUnits } from './forest.js';
import { buildStructuralIndex, type StructuralIndex, weightedNorm } from './index.js';
import { matchForests } from './matcher.js';
import { type NormalizedTree, parseAndNormalize } from './normalize.js';
import { AstParserUnavailableError, astLanguageForPath, preloadGrammars } from './parser.js';
import {
  AST_SEARCH_DEFAULTS,
  type AstCloneMatch,
  type AstCloneSearchOptions,
  type AstCloneSearchOutcome,
  type AstCloneSearchSeed,
  type AstForest,
  type AstLanguage,
  type AstMatchEvidence,
  type AstSeedRecord,
  type AstSeedSkipReason,
} from './types.js';

const SKIPPED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  '.hg',
  '.svn',
  '.shannon',
  'dist',
  'build',
  'out',
  'coverage',
  'target',
  '.gradle',
  '.mvn',
  '.idea',
  '.settings',
  '.mypy_cache',
  '.pytest_cache',
  '.ruff_cache',
  '.tox',
  'site-packages',
  '.next',
  '.nuxt',
  '.turbo',
  '.venv',
  'venv',
  '__pycache__',
  'vendor',
  'third_party',
  'thirdparty',
  'repos',
  'workspaces',
]);

/** Lines around a recorded line that may supply the anchor when the row itself holds no statement. */
const ANCHOR_WIDEN_LINES = 2;

type ResolvedOptions = { readonly [Key in keyof AstCloneSearchOptions]: AstCloneSearchOptions[Key] };

function resolveOptions(overrides: Partial<AstCloneSearchOptions>): ResolvedOptions {
  return {
    ...AST_SEARCH_DEFAULTS,
    ...overrides,
    baseWeights: { ...AST_SEARCH_DEFAULTS.baseWeights, ...(overrides.baseWeights ?? {}) },
  };
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let index = 0; index < text.length; index++) {
    if (text.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function excerptForLine(text: string, lineStarts: readonly number[], line: number, maxLength: number): string {
  const start = lineStarts[line - 1];
  if (start === undefined) return '';
  return text
    .slice(start, lineStarts[line] ?? text.length)
    .trim()
    .slice(0, maxLength);
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

interface LoadedSeedFile {
  readonly relPath: string;
  readonly language: AstLanguage;
  readonly tree: NormalizedTree;
  readonly hasError: boolean;
}

async function loadSeedFile(
  root: string,
  relPath: string,
  language: AstLanguage,
): Promise<LoadedSeedFile | AstSeedSkipReason> {
  let real: string;
  try {
    real = await fs.realpath(path.resolve(root, relPath));
  } catch {
    return 'seed_file_missing';
  }
  if (!isInside(root, real)) return 'seed_path_outside_repository';
  try {
    if (!(await fs.stat(real)).isFile()) return 'seed_path_not_regular_file';
    const text = await fs.readFile(real, 'utf8');
    const tree = await parseAndNormalize(language, text);
    return {
      relPath: path.relative(root, real).split(path.sep).join('/'),
      language,
      tree,
      hasError: tree.hasError,
    };
  } catch (error) {
    if (error instanceof AstParserUnavailableError) throw error;
    return 'seed_unreadable';
  }
}

function skippedRecord(
  seed: AstCloneSearchSeed,
  reason: AstSeedSkipReason,
  language: AstLanguage | undefined,
): AstSeedRecord {
  return {
    finding_id: seed.findingId,
    vulnerability_class: seed.vulnerabilityClass,
    seed_file: seed.file,
    seed_line: seed.line,
    language,
    status: 'skipped',
    reason,
    anchor_line: seed.line,
    anchor_candidates: 0,
    node_count: 0,
    context_depth: 0,
    retrieval_candidates: 0,
    reranked_candidates: 0,
    matched: 0,
  };
}

interface PreparedSeed {
  readonly recordIndex: number;
  readonly seed: AstCloneSearchSeed;
  readonly language: AstLanguage;
  readonly file: LoadedSeedFile;
  readonly forests: readonly AstForest[];
}

interface CorpusResult {
  readonly inputsByLanguage: Map<AstLanguage, Array<{ forest: AstForest; excerpt: string }>>;
  readonly indexedFiles: number;
  readonly parseFailedFiles: number;
  readonly truncated: boolean;
}

async function indexRepository(
  root: string,
  options: ResolvedOptions,
  languages: ReadonlySet<AstLanguage>,
): Promise<CorpusResult> {
  const inputsByLanguage = new Map<AstLanguage, Array<{ forest: AstForest; excerpt: string }>>();
  for (const language of languages) inputsByLanguage.set(language, []);
  let indexedFiles = 0;
  let parseFailedFiles = 0;
  let indexedForests = 0;
  let truncated = false;
  const directories = [root];

  while (directories.length) {
    const current = directories.pop();
    if (current === undefined) break;
    const entries = await fs.readdir(current, { withFileTypes: true }).catch(() => undefined);
    if (entries === undefined) continue;
    entries.sort((left, right) => left.name.localeCompare(right.name));
    let exhausted = false;
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) directories.push(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      const language = astLanguageForPath(entry.name);
      if (language === undefined || !languages.has(language)) continue;
      if (indexedFiles >= options.maxFiles || indexedForests >= options.maxIndexedForests) {
        truncated = true;
        exhausted = true;
        break;
      }
      let text: string;
      try {
        const stats = await fs.stat(absolute);
        if (stats.size > options.maxFileBytes) {
          truncated = true;
          continue;
        }
        text = await fs.readFile(absolute, 'utf8');
      } catch {
        continue;
      }
      let tree: NormalizedTree & { hasError: boolean };
      try {
        tree = await parseAndNormalize(language, text);
      } catch (error) {
        if (error instanceof AstParserUnavailableError) throw error;
        parseFailedFiles++;
        continue;
      }
      if (tree.hasError) {
        parseFailedFiles++;
        continue;
      }
      indexedFiles++;
      const relPath = path.relative(root, absolute).split(path.sep).join('/');
      const lineStarts = computeLineStarts(text);
      const buckets = inputsByLanguage.get(language);
      if (buckets === undefined) continue;
      const seen = new Set<string>();
      let perFile = 0;
      for (const statement of statementUnits(tree.root)) {
        if (perFile >= options.maxCandidatesPerFile || indexedForests >= options.maxIndexedForests) {
          truncated = true;
          break;
        }
        const anchor = primaryAnchor(statement);
        const built = buildForest(language, relPath, tree.root, tree.nodes, anchor, {
          siblingRadius: options.siblingRadius,
          maxAncestorDepth: options.maxAncestorDepth,
          minForestNodes: options.minForestNodes,
          maxForestNodes: options.maxForestNodes,
        });
        if (built.forest === undefined) continue;
        const key = `${String(statement.startLine)}\u0000${String(statement.endLine)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        perFile++;
        indexedForests++;
        buckets.push({
          forest: compactForest(built.forest),
          excerpt: excerptForLine(text, lineStarts, anchor.startLine, options.maxExcerptLength),
        });
      }
      if (exhausted) break;
    }
    if (exhausted) break;
  }

  return { inputsByLanguage, indexedFiles, parseFailedFiles, truncated };
}

export async function searchAstCloneCandidates(
  repoPath: string,
  seeds: readonly AstCloneSearchSeed[],
  overrides: Partial<AstCloneSearchOptions> = {},
): Promise<AstCloneSearchOutcome> {
  const options = resolveOptions(overrides);
  const root = await fs.realpath(repoPath);
  const records: AstSeedRecord[] = [];
  const preparedSeeds: PreparedSeed[] = [];
  const seedFileCache = new Map<string, LoadedSeedFile>();
  let truncated = false;
  let parserUnavailable = false;
  const seedParseFailedFiles = new Set<string>();
  let ambiguousAnchors = 0;

  const supportedLanguages = new Set<AstLanguage>();
  for (const seed of seeds) {
    const language = astLanguageForPath(seed.file);
    if (language !== undefined) supportedLanguages.add(language);
  }
  try {
    await preloadGrammars([...supportedLanguages].sort() as AstLanguage[]);
  } catch {
    parserUnavailable = true;
  }

  for (const [index, seed] of seeds.entries()) {
    if (index >= options.maxSeeds) {
      records.push(skippedRecord(seed, 'seed_limit', astLanguageForPath(seed.file)));
      truncated = true;
      continue;
    }
    const language = astLanguageForPath(seed.file);
    if (!Number.isInteger(seed.line) || seed.line < 1) {
      records.push(skippedRecord(seed, 'invalid_seed_line', language));
      continue;
    }
    if (language === undefined) {
      records.push(skippedRecord(seed, 'unsupported_language', undefined));
      continue;
    }
    if (parserUnavailable) {
      records.push(skippedRecord(seed, 'parser_not_available', language));
      continue;
    }
    let file = seedFileCache.get(seed.file);
    if (file === undefined) {
      let loaded: LoadedSeedFile | AstSeedSkipReason;
      try {
        loaded = await loadSeedFile(root, seed.file, language);
      } catch {
        parserUnavailable = true;
        records.push(skippedRecord(seed, 'parser_not_available', language));
        continue;
      }
      if (typeof loaded === 'string') {
        records.push(skippedRecord(seed, loaded, language));
        continue;
      }
      file = loaded;
      seedFileCache.set(seed.file, file);
    }
    if (file.hasError) {
      seedParseFailedFiles.add(file.relPath);
      records.push(skippedRecord(seed, 'parse_error', language));
      continue;
    }
    const found = findAnchorNodes(file.tree.nodes, seed.line, ANCHOR_WIDEN_LINES, options.maxAnchorAlternativesPerSeed);
    if (!found.anchors.length) {
      records.push(skippedRecord(seed, 'anchor_not_found', language));
      continue;
    }
    if (found.ambiguous) ambiguousAnchors++;
    const forests: AstForest[] = [];
    let tooSmall = false;
    for (const anchor of found.anchors) {
      const built = buildForest(language, file.relPath, file.tree.root, file.tree.nodes, anchor, {
        siblingRadius: options.siblingRadius,
        maxAncestorDepth: options.maxAncestorDepth,
        minForestNodes: options.minForestNodes,
        maxForestNodes: options.maxForestNodes,
      });
      if (built.forest !== undefined) forests.push(compactForest(built.forest));
      else if (built.reason === 'forest_too_small') tooSmall = true;
    }
    if (!forests.length) {
      records.push(skippedRecord(seed, tooSmall ? 'forest_too_small' : 'anchor_not_found', language));
      continue;
    }
    const nodeCount = forests.reduce((max, forest) => Math.max(max, forest.nodeCount), 0);
    const contextDepth = forests.reduce((max, forest) => Math.max(max, forest.contextPath.length), 0);
    records.push({
      finding_id: seed.findingId,
      vulnerability_class: seed.vulnerabilityClass,
      seed_file: seed.file,
      seed_line: seed.line,
      language,
      status: 'eligible',
      anchor_line: forests[0]?.anchorLine ?? seed.line,
      anchor_candidates: forests.length,
      node_count: nodeCount,
      context_depth: contextDepth,
      retrieval_candidates: 0,
      reranked_candidates: 0,
      matched: 0,
    });
    preparedSeeds.push({ recordIndex: records.length - 1, seed, language, file, forests });
  }

  const languages = new Set(preparedSeeds.map((prepared) => prepared.language));
  let corpus: CorpusResult = {
    inputsByLanguage: new Map(),
    indexedFiles: 0,
    parseFailedFiles: 0,
    truncated: false,
  };
  const indexes = new Map<AstLanguage, StructuralIndex>();
  let indexedForests = 0;
  if (!parserUnavailable && languages.size > 0) {
    corpus = await indexRepository(root, options, languages);
    truncated = truncated || corpus.truncated;
    for (const [language, inputs] of corpus.inputsByLanguage) {
      indexes.set(language, buildStructuralIndex(inputs, options.baseWeights));
      indexedForests += inputs.length;
    }
  }

  let retrievalCandidates = 0;
  let rerankedCandidates = 0;
  let unmappedAnchors = 0;
  let matcherBudgetExceeded = 0;
  const matchesBySeed = new Map<number, readonly AstCloneMatch[]>();
  for (const [seedIndex, prepared] of preparedSeeds.entries()) {
    const index = indexes.get(prepared.language);
    const perSeed: AstCloneMatch[] = [];
    let seedRetrieval = 0;
    let seedReranked = 0;
    let operationsLeft = options.maxMatchOperationsPerSeed;
    if (index !== undefined) {
      for (const seedForest of prepared.forests) {
        const seedFeatures = extractFeatures(seedForest);
        if (seedFeatures.size === 0) continue;
        const seedNorm = weightedNorm(index, seedFeatures);
        const candidates = index.retrieve(
          seedFeatures,
          seedNorm,
          options.maxCandidateForestsPerSeed,
          options.minRetrievalScore,
        );
        seedRetrieval += candidates.length;
        for (const candidate of candidates) {
          if (operationsLeft <= 0) {
            truncated = true;
            break;
          }
          const indexed = index.forests[candidate.forestId];
          if (indexed === undefined) continue;
          if (isSeedSelf(prepared.seed, indexed.forest)) continue;
          const outcome = matchForests(
            seedForest,
            indexed.forest,
            Math.min(options.maxMatcherCellsPerPair, operationsLeft),
          );
          operationsLeft -= outcome.operations;
          seedReranked++;
          if (outcome.budgetExceeded) {
            matcherBudgetExceeded++;
            continue;
          }
          if (!outcome.evidence.anchor_mapped) {
            unmappedAnchors++;
            continue;
          }
          if (outcome.similarity < options.minTreeSimilarity) continue;
          const evidence: AstMatchEvidence = { ...outcome.evidence, retrieval_score: candidate.score };
          perSeed.push(buildMatch(prepared.seed, indexed.forest, indexed.excerpt, outcome.similarity, evidence));
        }
      }
    }
    retrievalCandidates += seedRetrieval;
    rerankedCandidates += seedReranked;
    const deduped = dedupeMatches(perSeed).slice(0, options.maxPreciseMatchesPerSeed);
    matchesBySeed.set(seedIndex, deduped);
    const record = records[prepared.recordIndex];
    if (record !== undefined) {
      records[prepared.recordIndex] = {
        ...record,
        retrieval_candidates: seedRetrieval,
        reranked_candidates: seedReranked,
        matched: deduped.length,
      };
    }
  }

  const merged = interleaveMatches(matchesBySeed, options);
  if (merged.truncated) truncated = true;

  const skipped = records.filter((record) => record.status === 'skipped');
  const eligible = records.filter((record) => record.status === 'eligible');
  const skipReasons: Record<string, number> = {};
  for (const record of skipped) {
    const reason = record.reason ?? 'unknown';
    skipReasons[reason] = (skipReasons[reason] ?? 0) + 1;
  }
  const parserLanguageUnsupported = skipReasons.unsupported_language ?? 0;
  const parseFailedTotal = seedParseFailedFiles.size + corpus.parseFailedFiles;

  const statistics = {
    seed_count: records.length,
    eligible_seed_count: eligible.length,
    candidate_count: merged.matches.length,
    parse_failed_files: parseFailedTotal,
    indexed_forests: indexedForests,
    retrieval_candidates: retrievalCandidates,
    reranked_candidates: rerankedCandidates,
    unmapped_anchors: unmappedAnchors,
    ambiguous_anchors: ambiguousAnchors,
    matcher_budget_exceeded: matcherBudgetExceeded,
    parser_language_unsupported: parserLanguageUnsupported,
  };

  return {
    result: {
      schema_version: 3,
      algorithm: 'ast_structural_clone_v1',
      matches: merged.matches,
      skipped_seeds: skipped,
      truncated,
      statistics,
    },
    seeds: { schema_version: 3, algorithm: 'ast_structural_clone_v1', seeds: records, truncated },
    coverage: {
      schema_version: 3,
      algorithm: 'ast_structural_clone_v1',
      summary: {
        seeds_total: records.length,
        seeds_eligible: eligible.length,
        seeds_skipped: skipped.length,
        indexed_files: corpus.indexedFiles,
        indexed_forests: indexedForests,
        parse_failed_files: parseFailedTotal,
        retrieval_candidates: retrievalCandidates,
        reranked_candidates: rerankedCandidates,
        unmapped_anchors: unmappedAnchors,
        ambiguous_anchors: ambiguousAnchors,
        matcher_budget_exceeded: matcherBudgetExceeded,
        parser_language_unsupported: parserLanguageUnsupported,
        matched: merged.matches.length,
        truncated,
      },
      skip_reasons: skipReasons,
      seeds: records,
    },
  };
}

function isSeedSelf(seed: AstCloneSearchSeed, candidate: AstForest): boolean {
  return candidate.file === seed.file && candidate.startLine <= seed.line && seed.line <= candidate.endLine;
}

function buildMatch(
  seed: AstCloneSearchSeed,
  forest: AstForest,
  excerpt: string,
  similarity: number,
  evidence: AstMatchEvidence,
): AstCloneMatch {
  return {
    finding_id: seed.findingId,
    vulnerability_class: seed.vulnerabilityClass,
    seed_file: seed.file,
    seed_line: seed.line,
    match_file: forest.file,
    match_line: forest.anchorLine,
    candidate_start_line: forest.startLine,
    candidate_end_line: forest.endLine,
    score: Math.round(similarity * 10000) / 10000,
    excerpt,
    ast_evidence: {
      ...evidence,
      retrieval_score: Math.round(evidence.retrieval_score * 10000) / 10000,
    },
  };
}

function dedupeMatches(matches: readonly AstCloneMatch[]): AstCloneMatch[] {
  const best = new Map<string, AstCloneMatch>();
  for (const match of matches) {
    const key = `${match.finding_id}\u0000${match.match_file}\u0000${String(match.match_line)}`;
    const current = best.get(key);
    if (current === undefined || match.score > current.score) best.set(key, match);
  }
  return [...best.values()].sort(compareMatches);
}

function compareMatches(left: AstCloneMatch, right: AstCloneMatch): number {
  if (right.score !== left.score) return right.score - left.score;
  if (right.ast_evidence.retrieval_score !== left.ast_evidence.retrieval_score)
    return right.ast_evidence.retrieval_score - left.ast_evidence.retrieval_score;
  const byFinding = left.finding_id.localeCompare(right.finding_id);
  if (byFinding !== 0) return byFinding;
  const byFile = left.match_file.localeCompare(right.match_file);
  if (byFile !== 0) return byFile;
  return left.match_line - right.match_line;
}

function interleaveMatches(
  lists: ReadonlyMap<number, readonly AstCloneMatch[]>,
  options: ResolvedOptions,
): { matches: AstCloneMatch[]; truncated: boolean } {
  const seedIndexes = [...lists.keys()].sort((left, right) => left - right);
  const cursors = new Map<number, number>();
  const seen = new Set<string>();
  const result: AstCloneMatch[] = [];
  let truncated = false;
  for (;;) {
    let progressed = false;
    for (const seedIndex of seedIndexes) {
      const list = lists.get(seedIndex) ?? [];
      const cursor = cursors.get(seedIndex) ?? 0;
      if (cursor >= list.length || cursor >= options.maxMatchesPerSeed) continue;
      cursors.set(seedIndex, cursor + 1);
      progressed = true;
      const match = list[cursor];
      if (match === undefined) continue;
      if (result.length >= options.maxTotalMatches) {
        truncated = true;
        break;
      }
      const key = `${match.finding_id}\u0000${match.match_file}\u0000${String(match.match_line)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push(match);
    }
    if (result.length >= options.maxTotalMatches || !progressed) break;
  }
  for (const seedIndex of seedIndexes) {
    const list = lists.get(seedIndex) ?? [];
    if ((cursors.get(seedIndex) ?? 0) < Math.min(list.length, options.maxMatchesPerSeed)) truncated = true;
  }
  return { matches: result, truncated };
}
