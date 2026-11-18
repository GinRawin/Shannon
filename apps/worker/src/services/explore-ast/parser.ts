// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Tree-sitter bootstrap for Explore v3.
 *
 * The parser is loaded from the fixed `web-tree-sitter` runtime plus one pinned grammar WASM per
 * language. Nothing is compiled at install time and nothing is downloaded at scan time: the WASM
 * files ship with the pinned packages under `node_modules`, which the production image already
 * copies. A missing grammar is reported as a hard, typed failure rather than a silent fallback to
 * the lexer.
 */

import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { Language, Parser } from 'web-tree-sitter';
import type { AstLanguage } from './types.js';

const require = createRequire(import.meta.url);

/** Raised when the WebAssembly parser or one of the pinned grammars cannot be loaded. */
export class AstParserUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'AstParserUnavailableError';
  }
}

interface GrammarSpec {
  readonly packageName: string;
  readonly wasmFile: string;
}

const GRAMMAR_BY_LANGUAGE: Readonly<Record<AstLanguage, GrammarSpec>> = Object.freeze({
  javascript: { packageName: 'tree-sitter-javascript', wasmFile: 'tree-sitter-javascript.wasm' },
  typescript: { packageName: 'tree-sitter-typescript', wasmFile: 'tree-sitter-typescript.wasm' },
  tsx: { packageName: 'tree-sitter-typescript', wasmFile: 'tree-sitter-tsx.wasm' },
  java: { packageName: 'tree-sitter-java', wasmFile: 'tree-sitter-java.wasm' },
});

const LANGUAGE_BY_EXTENSION: ReadonlyMap<string, AstLanguage> = new Map<string, AstLanguage>([
  ['.js', 'javascript'],
  ['.jsx', 'javascript'],
  ['.mjs', 'javascript'],
  ['.cjs', 'javascript'],
  ['.ts', 'typescript'],
  ['.mts', 'typescript'],
  ['.cts', 'typescript'],
  ['.tsx', 'tsx'],
  ['.java', 'java'],
]);

/** Language for a repository-relative path, or `undefined` when the extension is unsupported. */
export function astLanguageForPath(relPath: string): AstLanguage | undefined {
  return LANGUAGE_BY_EXTENSION.get(path.extname(relPath).toLowerCase());
}

let parserInitialization: Promise<void> | undefined;
const languageCache = new Map<AstLanguage, Promise<Language>>();
const parserCache = new Map<AstLanguage, Promise<Parser>>();

function resolvePackageFile(packageName: string, file: string): string {
  const packageJson = require.resolve(`${packageName}/package.json`);
  return path.join(path.dirname(packageJson), file);
}

async function initializeParser(): Promise<void> {
  parserInitialization ??= Parser.init({
    locateFile: () => require.resolve('web-tree-sitter/web-tree-sitter.wasm'),
  });
  return parserInitialization;
}

async function loadLanguage(language: AstLanguage): Promise<Language> {
  let cached = languageCache.get(language);
  if (cached === undefined) {
    cached = (async () => {
      await initializeParser();
      const spec = GRAMMAR_BY_LANGUAGE[language];
      const wasmPath = resolvePackageFile(spec.packageName, spec.wasmFile);
      const bytes = await fs.readFile(wasmPath);
      return Language.load(bytes);
    })();
    languageCache.set(language, cached);
    // A failed load must not poison the cache: drop it so a later attempt can retry.
    cached.catch(() => languageCache.delete(language));
  }
  return cached;
}

/** A parser bound to one language grammar, reused across files of that language. */
export async function parserForLanguage(language: AstLanguage): Promise<Parser> {
  let cached = parserCache.get(language);
  if (cached === undefined) {
    cached = (async () => {
      const lang = await loadLanguage(language);
      const parser = new Parser();
      parser.setLanguage(lang);
      return parser;
    })();
    parserCache.set(language, cached);
    cached.catch(() => parserCache.delete(language));
  }
  return cached;
}

/** Load every grammar once so a missing deployment resource fails before any seed is searched. */
export async function preloadGrammars(languages: readonly AstLanguage[]): Promise<void> {
  for (const language of languages) await parserForLanguage(language);
}

export interface ParsedSource {
  readonly language: AstLanguage;
  readonly text: string;
  readonly rootType: string;
  readonly hasError: boolean;
  /** Raw Tree-sitter root; callers must convert it to a normalized AST in the same tick. */
  readonly root: import('web-tree-sitter').Node;
}

/**
 * Parse one file. The returned root exposes Tree-sitter `Node`s; callers normalize immediately and
 * never retain them, because the underlying tree is released on the next parse with this parser.
 */
export async function parseSource(language: AstLanguage, text: string): Promise<ParsedSource> {
  const parser = await parserForLanguage(language);
  const tree = parser.parse(text);
  if (tree === null) throw new AstParserUnavailableError(`Tree-sitter returned no tree for ${language} source.`);
  const root = tree.rootNode;
  return { language, text, rootType: root.type, hasError: root.hasError, root };
}

/** True when the pinned grammars and the WebAssembly runtime can be loaded on this host. */
export async function grammarsAvailable(languages: readonly AstLanguage[]): Promise<boolean> {
  try {
    await preloadGrammars(languages);
    return true;
  } catch {
    return false;
  }
}
