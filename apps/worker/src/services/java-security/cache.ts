// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Snapshot identity, in-process single-flight, and a workspace-isolated disk cache.
 *
 * The snapshot binds the index to the *content* of the scanned files (per-file SHA-256), the rule
 * version, the scan parameters, and the index schema version — never to Git HEAD alone, so
 * uncommitted edits and rule upgrades both invalidate it. Concurrent callers in one process share a
 * single build; a new process re-hashes files cheaply and reuses the parsed index from disk.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { indexFiles, type ScanOptions, scanSourceFiles } from './indexer.js';
import { loadRuleSet } from './rules.js';
import { INDEX_SCHEMA_VERSION, type RawIndexFile } from './types.js';

const CACHE_SCHEMA_VERSION = 1;
const CACHE_RELATIVE_DIR = path.join('.shannon', 'cache', 'security-candidates', 'v1');

export interface SecurityCandidatesConfig {
  readonly enabled: boolean;
  readonly timeoutMs: number;
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly maxResults: number;
}

function positiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Read the feature's tunables from the environment, applying the documented defaults. */
export function loadSecurityCandidatesConfig(env: NodeJS.ProcessEnv = process.env): SecurityCandidatesConfig {
  const enabled = env.SHANNON_SECURITY_CANDIDATES_ENABLED !== 'false';
  return {
    enabled,
    timeoutMs: positiveInt(env.SHANNON_SECURITY_CANDIDATES_TIMEOUT_MS, 30_000),
    maxFileBytes: positiveInt(env.SHANNON_SECURITY_CANDIDATES_MAX_FILE_BYTES, 1_048_576),
    maxFiles: positiveInt(env.SHANNON_SECURITY_CANDIDATES_MAX_FILES, 20_000),
    maxResults: positiveInt(env.SHANNON_SECURITY_CANDIDATES_MAX_RESULTS, 100),
  };
}

export interface IndexStats {
  readonly filesScanned: number;
  readonly filesSkipped: number;
  readonly parseErrors: number;
  readonly timeout: boolean;
}

export interface IndexHandle {
  readonly index: RawIndexFile;
  readonly stats: IndexStats;
  readonly warnings: readonly string[];
  readonly fromCache: boolean;
}

const EXCLUDED_DIRS: readonly string[] = [
  'target',
  'build',
  '.gradle',
  '.git',
  'node_modules',
  'vendor',
  '.shannon',
  'out',
  'dist',
  '.idea',
  '.mvn',
  '.settings',
  'generated-sources',
];

function scanOptions(config: SecurityCandidatesConfig): ScanOptions {
  return {
    maxFileBytes: config.maxFileBytes,
    maxFiles: config.maxFiles,
    timeoutMs: config.timeoutMs,
    includedExtensions: ['.java'],
    excludedDirs: EXCLUDED_DIRS,
  };
}

function scanParamsHash(config: SecurityCandidatesConfig): string {
  return createHash('sha256')
    .update(JSON.stringify({ maxFileBytes: config.maxFileBytes, maxFiles: config.maxFiles, excluded: EXCLUDED_DIRS }))
    .digest('hex');
}

interface Manifest {
  readonly schemaVersion: number;
  readonly indexSchemaVersion: number;
  readonly ruleVersion: string;
  readonly rulesetHash: string;
  readonly scanParamsHash: string;
  readonly snapshotId: string;
  readonly stats: IndexStats;
}

function cacheDirFor(sourceDir: string): string {
  return path.join(sourceDir, CACHE_RELATIVE_DIR);
}

async function readJsonFile<T>(filePath: string): Promise<T | undefined> {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8')) as T;
  } catch {
    return undefined;
  }
}

async function writeAtomic(filePath: string, content: string): Promise<void> {
  const tmp = `${filePath}.tmp.${process.pid}.${Math.random().toString(36).slice(2)}`;
  await fs.writeFile(tmp, content, 'utf8');
  await fs.rename(tmp, filePath);
}

/** Best-effort cross-process lock; correctness does not depend on it (builds are idempotent). */
async function withBuildLock<T>(cacheDir: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = path.join(cacheDir, 'build.lock');
  const staleMs = 60_000;
  const deadline = Date.now() + 30_000;
  let held = false;
  while (Date.now() < deadline) {
    try {
      const handle = await fs.open(lockPath, 'wx');
      await handle.writeFile(`${process.pid} ${new Date().toISOString()}`, 'utf8');
      await handle.close();
      held = true;
      break;
    } catch {
      try {
        const stat = await fs.stat(lockPath);
        if (Date.now() - stat.mtimeMs > staleMs) await fs.unlink(lockPath);
      } catch {
        // lock disappeared between attempts; retry immediately
      }
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }
  try {
    return await fn();
  } finally {
    if (held) await fs.unlink(lockPath).catch(() => undefined);
  }
}

function snapshotIdFor(
  entries: readonly { relPath: string; sha256: string }[],
  rulesetHash: string,
  paramsHash: string,
): string {
  const manifest = entries
    .map((entry) => `${entry.relPath}:${entry.sha256}`)
    .sort()
    .join('\n');
  return createHash('sha256')
    .update(`${manifest}\n${rulesetHash}\n${paramsHash}\n${INDEX_SCHEMA_VERSION}\n${CACHE_SCHEMA_VERSION}`)
    .digest('hex');
}

async function computeIndex(sourceDir: string, config: SecurityCandidatesConfig): Promise<IndexHandle> {
  const warnings: string[] = [];
  let rulesetHash: string;
  let ruleVersion: string;
  try {
    const ruleSet = loadRuleSet();
    rulesetHash = ruleSet.hash;
    ruleVersion = ruleSet.version;
  } catch (error) {
    throw new Error(`security rule set unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }

  const scan = await scanSourceFiles(sourceDir, scanOptions(config));
  warnings.push(...scan.warnings);
  // MyBatis mapper XML is deferred to a later revision. Surface the gap on every call (cache hit or
  // miss) so the agent never reads a Java-only result as complete SQL-sink coverage.
  warnings.push(
    'MyBatis mapper XML scanning is not enabled in this build; XML dynamic-interpolation sinks are not covered',
  );
  const files = [...scan.files].sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));
  const paramsHash = scanParamsHash(config);
  const snapshotId = snapshotIdFor(files, rulesetHash, paramsHash);

  const cacheDir = cacheDirFor(sourceDir);
  const indexPath = path.join(cacheDir, 'index.json');
  const manifestPath = path.join(cacheDir, 'manifest.json');

  const manifest = await readJsonFile<Manifest>(manifestPath);
  if (manifest?.snapshotId === snapshotId && manifest.indexSchemaVersion === INDEX_SCHEMA_VERSION) {
    const cached = await readJsonFile<RawIndexFile>(indexPath);
    if (cached !== undefined && cached.snapshotId === snapshotId && Array.isArray(cached.files)) {
      return { index: cached, stats: manifest.stats, warnings, fromCache: true };
    }
    warnings.push('security candidate cache manifest matched but the index was unreadable; rebuilding');
  }

  const built = await indexFiles(sourceDir, files, { timeoutMs: config.timeoutMs });
  warnings.push(...built.warnings);
  const stats: IndexStats = {
    filesScanned: files.length,
    filesSkipped: scan.skipped,
    parseErrors: built.parseErrors,
    timeout: scan.truncated || built.truncated,
  };
  const index: RawIndexFile = {
    schemaVersion: CACHE_SCHEMA_VERSION,
    indexSchemaVersion: INDEX_SCHEMA_VERSION,
    ruleVersionHash: rulesetHash,
    scanParamsHash: paramsHash,
    snapshotId,
    filesScanned: files.length,
    filesSkipped: scan.skipped,
    parseErrors: built.parseErrors,
    truncated: stats.timeout,
    files: built.entries,
  };

  try {
    await fs.mkdir(cacheDir, { recursive: true });
    await withBuildLock(cacheDir, async () => {
      await writeAtomic(indexPath, JSON.stringify(index));
      const nextManifest: Manifest = {
        schemaVersion: CACHE_SCHEMA_VERSION,
        indexSchemaVersion: INDEX_SCHEMA_VERSION,
        ruleVersion,
        rulesetHash,
        scanParamsHash: paramsHash,
        snapshotId,
        stats,
      };
      await writeAtomic(manifestPath, JSON.stringify(nextManifest));
    });
  } catch (error) {
    warnings.push(
      `failed to persist security candidate cache: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  return { index, stats, warnings, fromCache: false };
}

const inFlight = new Map<string, Promise<IndexHandle>>();

/** Resolve the parsed index for a source root, sharing one build per snapshot in this process. */
export async function getSecurityIndex(sourceDir: string, config: SecurityCandidatesConfig): Promise<IndexHandle> {
  const key = `${path.resolve(sourceDir)}|${scanParamsHash(config)}`;
  const existing = inFlight.get(key);
  if (existing !== undefined) return existing;
  const promise = computeIndex(sourceDir, config);
  inFlight.set(key, promise);
  try {
    return await promise;
  } catch (error) {
    inFlight.delete(key);
    throw error;
  }
}

/** Test-only: drop the in-process index cache. */
export function resetSecurityIndexCache(): void {
  inFlight.clear();
}
