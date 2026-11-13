/**
 * Deterministic Type-2 / Type-3 code-clone retrieval for the Explore stage.
 *
 * Explore takes a record-verified sink location, cuts a local token window around the recorded
 * line, and looks for structurally similar windows elsewhere in the same repository. Similarity
 * is lexical and structural: identifiers and literals are erased, keywords and punctuation are
 * kept, so variable renames and literal swaps (Type-2) and small insertions or deletions within
 * shared code (Type-3) still match.
 *
 * Each supported language has its own tokenizer behind one normalization contract (erased
 * identifiers and literals, verbatim keywords and punctuation), and a seed is only ever compared
 * with windows of its own language. Every non-JS/TS/Java extension is still reported as
 * `unsupported_language` rather than being parsed by a guessed grammar.
 *
 * The module is deliberately free of Agent/Temporal dependencies so it can be exercised offline
 * against a fixture repository, and it never calls an LLM. It only reports *similar code*; the
 * downstream expansion pass decides whether a candidate is actually vulnerable.
 */

import fs from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

type TypeScriptModule = typeof import('typescript');

const require = createRequire(import.meta.url);
let loadedTypeScript: TypeScriptModule | undefined;

function typeScript(): TypeScriptModule {
  loadedTypeScript ??= require('typescript') as TypeScriptModule;
  return loadedTypeScript;
}

/** Tunable retrieval parameters. Defaults favour recall on labelled variants, then precision. */
export const CLONE_SEARCH_DEFAULTS = Object.freeze({
  /** Token n-gram width used for the inverted index and the containment score. */
  kGram: 5,
  /** Preferred number of tokens in the seed window. */
  seedTargetTokens: 80,
  /** Lower clamp for the seed window extracted around the recorded line. */
  seedMinTokens: 40,
  /** Upper clamp for the seed window extracted around the recorded line. */
  seedMaxTokens: 120,
  /** Seeds below this token count cannot be searched reliably and are skipped. */
  minSeedTokens: 25,
  /** Candidate windows are at least this many tokens (or the whole file when it is smaller). */
  windowMinTokens: 50,
  /** Candidate windows are at most this many tokens. */
  windowMaxTokens: 150,
  /** Sliding-window stride. */
  windowStepTokens: 10,
  /** Minimum fraction of the seed's k-grams that must appear in a candidate window. */
  initialSimilarityThreshold: 0.55,
  /** Minimum shared k-grams, so a few incidental n-grams cannot create a candidate. */
  minSharedKgrams: 8,
  /** Fraction of the seed window that must align to a candidate before a match is reported. */
  minAlignedSeedRatio: 0.5,
  /** How many top-scoring windows per seed are refined with a sequence alignment. */
  alignmentCandidates: 20,
  /** Maximum number of seeds searched in one pass. */
  maxSeeds: 30,
  /** Maximum matches returned per seed. */
  maxMatchesPerSeed: 10,
  /** Maximum matches returned across all seeds. */
  maxTotalMatches: 100,
  /** Repository scan caps. Exceeding any of them marks the result as truncated. */
  maxFiles: 5_000,
  maxFileBytes: 1_000_000,
  maxTotalTokens: 800_000,
  maxWindows: 120_000,
  /** How far the anchor search may walk from the recorded line when that line holds no tokens. */
  anchorWidenLines: 3,
  /** Excerpt length stored with each match. */
  maxExcerptLength: 800,
});

export type CloneSearchOptions = typeof CLONE_SEARCH_DEFAULTS;

export type CloneSeedSkipReason =
  | 'invalid_seed_line'
  | 'unsupported_language'
  | 'seed_file_missing'
  | 'seed_path_outside_repository'
  | 'seed_path_not_regular_file'
  | 'seed_unreadable'
  | 'seed_too_short'
  | 'no_anchor_token'
  | 'seed_limit';

/** One recorded, record-verified sink location to search from. */
export interface CloneSearchSeed {
  readonly findingId: string;
  readonly vulnerabilityClass: string;
  /** Repository-relative POSIX path, exactly as recorded by the exploit collector. */
  readonly file: string;
  /** One-based recorded sink line. */
  readonly line: number;
}

export interface CloneMatch {
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
}

export interface CloneSeedRecord {
  readonly finding_id: string;
  readonly vulnerability_class: string;
  readonly seed_file: string;
  readonly seed_line: number;
  /** Tokenizer language of the seed file; absent when its extension is unsupported. */
  readonly language?: CloneLanguage;
  readonly status: 'eligible' | 'skipped';
  readonly token_count: number;
  readonly seed_start_line: number;
  readonly seed_end_line: number;
  readonly anchor_line: number;
  readonly anchor_token: string;
  readonly candidates_considered: number;
  readonly candidates_unaligned: number;
  readonly matched: number;
  readonly reason?: CloneSeedSkipReason;
}

/** Payload of `explore_search_results.json`; the top-level `matches` array is the Expansion entry point. */
export interface CloneSearchResult {
  readonly schema_version: 2;
  readonly algorithm: 'normalized_token_clone_v1';
  readonly matches: CloneMatch[];
  readonly skipped_seeds: CloneSeedRecord[];
  readonly truncated: boolean;
  readonly statistics: {
    readonly seed_count: number;
    readonly eligible_seed_count: number;
    readonly candidate_count: number;
  };
}

export interface CloneSeedsDocument {
  readonly schema_version: 2;
  readonly algorithm: 'normalized_token_clone_v1';
  readonly seeds: CloneSeedRecord[];
  readonly truncated: boolean;
}

export interface CloneCoverageDocument {
  readonly schema_version: 2;
  readonly algorithm: 'normalized_token_clone_v1';
  readonly summary: {
    readonly seeds_total: number;
    readonly seeds_eligible: number;
    readonly seeds_skipped: number;
    readonly indexed_files: number;
    readonly indexed_tokens: number;
    readonly indexed_windows: number;
    readonly skipped_files: number;
    readonly unaligned_candidates: number;
    readonly matched: number;
    readonly truncated: boolean;
  };
  readonly skip_reasons: Record<string, number>;
  readonly seeds: CloneSeedRecord[];
}

export interface CloneSearchOutcome {
  readonly result: CloneSearchResult;
  readonly seeds: CloneSeedsDocument;
  readonly coverage: CloneCoverageDocument;
}

/**
 * Languages this pass tokenizes. A seed is admitted only when its own extension maps here, and a
 * candidate window is only ever compared against a window of the seed's language, so a Java sink
 * can never be matched against a JavaScript file that happens to share punctuation and keywords.
 */
export type CloneLanguage = 'typescript' | 'java';

const LANGUAGE_BY_EXTENSION: ReadonlyMap<string, CloneLanguage> = new Map<string, CloneLanguage>([
  ['.ts', 'typescript'],
  ['.tsx', 'typescript'],
  ['.mts', 'typescript'],
  ['.cts', 'typescript'],
  ['.js', 'typescript'],
  ['.jsx', 'typescript'],
  ['.mjs', 'typescript'],
  ['.cjs', 'typescript'],
  ['.java', 'java'],
]);

/** The tokenizer language for a repository-relative path, or `undefined` when it is unsupported. */
export function cloneLanguageForPath(relPath: string): CloneLanguage | undefined {
  return LANGUAGE_BY_EXTENSION.get(path.extname(relPath).toLowerCase());
}


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
  // Java build output: generated sources under target/ are byte-copies of the real ones, and
  // retrieving them as Type-1 clones would spend the whole match budget on duplicates.
  'target',
  '.gradle',
  '.mvn',
  '.idea',
  '.settings',
  // Python caches and virtualenvs, when a Java project carries helper scripts.
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

interface NormalizedToken {
  readonly norm: string;
  readonly line: number;
}

interface IndexedFile {
  readonly relPath: string;
  readonly language: CloneLanguage;
  readonly text: string;
  readonly lineStarts: number[];
  readonly tokens: NormalizedToken[];
}

interface TokenWindow {
  readonly fileIndex: number;
  readonly startToken: number;
  readonly endToken: number;
  readonly kgrams: Uint32Array;
}

interface RankedCandidate {
  readonly windowId: number;
  readonly shared: number;
  readonly score: number;
}

interface IndexedCorpus {
  readonly files: IndexedFile[];
  readonly windows: TokenWindow[];
  readonly inverted: Map<number, number[]>;
  readonly idsByPath: Map<string, Int32Array>;
  readonly interned: Map<string, number>;
  readonly totalTokens: number;
  readonly skippedFiles: number;
  readonly truncated: boolean;
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function computeLineStarts(text: string): number[] {
  const lineStarts = [0];
  for (let index = 0; index < text.length; index++) {
    if (text.charCodeAt(index) === 10) lineStarts.push(index + 1);
  }
  return lineStarts;
}

function lineForOffset(lineStarts: readonly number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if ((lineStarts[mid] ?? 0) <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/**
 * Normalize one scanner token. The exact text of identifiers and literals is discarded so a
 * rename or literal swap does not change the token sequence, while keywords and punctuation keep
 * their shape so control flow and call structure survive.
 */
function normalizeToken(ts: TypeScriptModule, kind: number, raw: string): string {
  switch (kind) {
    case ts.SyntaxKind.Identifier:
    case ts.SyntaxKind.PrivateIdentifier:
      return 'IDENT';
    case ts.SyntaxKind.StringLiteral:
    case ts.SyntaxKind.NoSubstitutionTemplateLiteral:
    case ts.SyntaxKind.TemplateHead:
    case ts.SyntaxKind.TemplateMiddle:
    case ts.SyntaxKind.TemplateTail:
    case ts.SyntaxKind.JsxText:
    case ts.SyntaxKind.JsxTextAllWhiteSpaces:
      return 'STR';
    case ts.SyntaxKind.NumericLiteral:
    case ts.SyntaxKind.BigIntLiteral:
      return 'NUM';
    case ts.SyntaxKind.RegularExpressionLiteral:
      return 'REGEX';
    default:
      return kind >= ts.SyntaxKind.FirstKeyword && kind <= ts.SyntaxKind.LastKeyword ? raw.toLowerCase() : raw;
  }
}

/**
 * Tokens after which a `/` opens a regular-expression literal instead of dividing. The scanner
 * has no parser context, so this covers expression-start positions (operators, opening
 * punctuation, and the keywords that must be followed by an expression) and leaves every other
 * slash as a division operator.
 */
let cachedRegexPrecedingKinds: Set<number> | undefined;

function regexPrecedingKinds(): ReadonlySet<number> {
  const ts = typeScript();
  cachedRegexPrecedingKinds ??= new Set([
    ts.SyntaxKind.OpenParenToken,
    ts.SyntaxKind.OpenBracketToken,
    ts.SyntaxKind.OpenBraceToken,
    ts.SyntaxKind.CloseBraceToken,
    ts.SyntaxKind.CommaToken,
    ts.SyntaxKind.SemicolonToken,
    ts.SyntaxKind.ColonToken,
    ts.SyntaxKind.QuestionToken,
    ts.SyntaxKind.EqualsToken,
    ts.SyntaxKind.EqualsGreaterThanToken,
    ts.SyntaxKind.PlusToken,
    ts.SyntaxKind.MinusToken,
    ts.SyntaxKind.AsteriskToken,
    ts.SyntaxKind.PercentToken,
    ts.SyntaxKind.AmpersandToken,
    ts.SyntaxKind.AmpersandAmpersandToken,
    ts.SyntaxKind.BarToken,
    ts.SyntaxKind.BarBarToken,
    ts.SyntaxKind.ExclamationToken,
    ts.SyntaxKind.LessThanToken,
    ts.SyntaxKind.GreaterThanToken,
    ts.SyntaxKind.ReturnKeyword,
    ts.SyntaxKind.TypeOfKeyword,
    ts.SyntaxKind.InstanceOfKeyword,
    ts.SyntaxKind.InKeyword,
    ts.SyntaxKind.OfKeyword,
    ts.SyntaxKind.NewKeyword,
    ts.SyntaxKind.DeleteKeyword,
    ts.SyntaxKind.VoidKeyword,
    ts.SyntaxKind.CaseKeyword,
    ts.SyntaxKind.DoKeyword,
    ts.SyntaxKind.ElseKeyword,
    ts.SyntaxKind.YieldKeyword,
    ts.SyntaxKind.AwaitKeyword,
    ts.SyntaxKind.ThrowKeyword,
    ts.SyntaxKind.ExtendsKeyword,
  ]);
  return cachedRegexPrecedingKinds;
}

/**
 * Tokenize with the TypeScript scanner. The scanner is context free, so this drives the two
 * re-scans the parser normally requests: template continuations inside `${...}` and slash tokens
 * that are really regular-expression literals. Without them a single backtick or regular
 * expression silently swallows the rest of the file into one token.
 */
function tokenizeTypeScript(text: string): NormalizedToken[] {
  const ts = typeScript();
  const lineStarts = computeLineStarts(text);
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, ts.LanguageVariant.Standard, text);
  const tokens: NormalizedToken[] = [];
  let templateDepth = 0;
  let previousKind = -1;
  for (;;) {
    let kind = scanner.scan();
    if (kind === ts.SyntaxKind.EndOfFileToken) break;
    if (kind === ts.SyntaxKind.CloseBraceToken && templateDepth > 0) {
      kind = scanner.reScanTemplateToken(false);
    } else if (
      (kind === ts.SyntaxKind.SlashToken || kind === ts.SyntaxKind.SlashEqualsToken) &&
      regexPrecedingKinds().has(previousKind)
    ) {
      kind = scanner.reScanSlashToken();
    }
    // A template head opens one substitution; a rescan inside it returns TemplateMiddle (same
    // substitution depth) or TemplateTail (the template closed).
    if (kind === ts.SyntaxKind.TemplateHead) templateDepth++;
    else if (kind === ts.SyntaxKind.TemplateTail) templateDepth = Math.max(0, templateDepth - 1);
    const start = scanner.getTokenPos();
    const norm = normalizeToken(ts, kind, text.slice(start, scanner.getTextPos()));
    previousKind = kind;
    if (norm) tokens.push({ norm, line: lineForOffset(lineStarts, start) });
  }
  return tokens;
}

/**
 * Java keywords (JLS §3.9) plus `true`/`false`/`null`. Contextual keywords such as `var` or
 * `record` stay identifiers: they are legal identifiers too, and erasing them keeps a rename from
 * changing the token sequence.
 */
const JAVA_KEYWORDS = new Set([
  'abstract',
  'assert',
  'boolean',
  'break',
  'byte',
  'case',
  'catch',
  'char',
  'class',
  'const',
  'continue',
  'default',
  'do',
  'double',
  'else',
  'enum',
  'extends',
  'final',
  'finally',
  'float',
  'for',
  'goto',
  'if',
  'implements',
  'import',
  'instanceof',
  'int',
  'interface',
  'long',
  'native',
  'new',
  'package',
  'private',
  'protected',
  'public',
  'return',
  'short',
  'static',
  'strictfp',
  'super',
  'switch',
  'synchronized',
  'this',
  'throw',
  'throws',
  'transient',
  'try',
  'void',
  'volatile',
  'while',
  'true',
  'false',
  'null',
]);

/** Java punctuation and operators, longest first inside each leading character group. */
const JAVA_OPERATORS: readonly string[] = [
  '>>>=',
  '>>>',
  '>>=',
  '>>',
  '>=',
  '>',
  '<<=',
  '<<',
  '<=',
  '<',
  '...',
  '.',
  '->',
  '--',
  '-=',
  '-',
  '++',
  '+=',
  '+',
  '*=',
  '*',
  '/=',
  '/',
  '%=',
  '%',
  '&&',
  '&=',
  '&',
  '||',
  '|=',
  '|',
  '^=',
  '^',
  '==',
  '=',
  '!=',
  '!',
  '::',
  ':',
  '~',
  '?',
  '@',
  '{',
  '}',
  '(',
  ')',
  '[',
  ']',
  ';',
  ',',
];

/** Operators bucketed by their first character, keeping the longest-first order above. */
const JAVA_OPERATORS_BY_FIRST: ReadonlyMap<string, readonly string[]> = (() => {
  const byFirst = new Map<string, string[]>();
  for (const operator of JAVA_OPERATORS) {
    const first = operator.slice(0, 1);
    const bucket = byFirst.get(first);
    if (bucket === undefined) byFirst.set(first, [operator]);
    else bucket.push(operator);
  }
  return byFirst;
})();

function isAsciiDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

/** Java identifier start: letters, `_`, `$`, and anything non-ASCII (Unicode letters). */
function isJavaIdentifierStart(code: number): boolean {
  return code === 95 || code === 36 || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code > 127;
}

function isJavaIdentifierPart(code: number): boolean {
  return isJavaIdentifierStart(code) || isAsciiDigit(code);
}

/** Advance past a `//` comment to its line break (exclusive). */
function skipToLineEnd(text: string, start: number): number {
  let index = start;
  while (index < text.length && text.charCodeAt(index) !== 10 && text.charCodeAt(index) !== 13) index += 1;
  return index;
}

/** Advance past a block comment (slash-star through star-slash). Java block comments do not nest. */
function skipBlockComment(text: string, start: number): number {
  let index = start + 2;
  while (index < text.length) {
    if (text.charCodeAt(index) === 42 /* * */ && text.charCodeAt(index + 1) === 47 /* / */) return index + 2;
    index += 1;
  }
  return text.length;
}

/**
 * Advance past a quoted literal and return the index one past its closing delimiter. An
 * unterminated single-line literal stops at the line break, and an unterminated text block stops
 * at end of file: a single runaway token would silently destroy the whole file's token stream,
 * which is worse than one wrong token.
 */
function skipJavaQuoted(text: string, start: number, delimiter: string, allowLineBreaks: boolean): number {
  let index = start + delimiter.length;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (code === 92 /* backslash */) {
      index += 2;
      continue;
    }
    if (!allowLineBreaks && (code === 10 || code === 13)) return index;
    if (text.startsWith(delimiter, index)) return index + delimiter.length;
    index += 1;
  }
  return text.length;
}

/** Consume a numeric literal: radix prefixes, underscores, exponents, and type suffixes. */
function scanJavaNumber(text: string, start: number): number {
  let index = start;
  while (index < text.length) {
    const code = text.charCodeAt(index);
    if (isJavaIdentifierPart(code)) {
      index += 1;
      continue;
    }
    // A `.` only continues the literal when a digit follows, so a member access is never eaten.
    if (code === 46 /* . */ && isAsciiDigit(text.charCodeAt(index + 1))) {
      index += 1;
      continue;
    }
    break;
  }
  return index;
}

/**
 * Tokenize Java source into the shared normalization contract: identifiers, strings, character
 * literals, text blocks, and numbers are erased; keywords, operators, and punctuation keep their
 * shape. This is a lexer, not a parser, so `<` and `>>` are matched as the longest operator and a
 * `\uXXXX` escape is not decoded.
 */
function tokenizeJava(text: string): NormalizedToken[] {
  const lineStarts = computeLineStarts(text);
  const tokens: NormalizedToken[] = [];
  const length = text.length;
  let index = 0;
  const push = (norm: string, start: number): void => {
    tokens.push({ norm, line: lineForOffset(lineStarts, start) });
  };
  while (index < length) {
    const code = text.charCodeAt(index);
    if (code === 32 || code === 9 || code === 10 || code === 13 || code === 12 || code === 11) {
      index += 1;
      continue;
    }
    if (code === 47 /* / */ && text.charCodeAt(index + 1) === 47 /* / */) {
      index = skipToLineEnd(text, index);
      continue;
    }
    if (code === 47 /* / */ && text.charCodeAt(index + 1) === 42 /* * */) {
      index = skipBlockComment(text, index);
      continue;
    }
    if (code === 34 /* " */) {
      const start = index;
      const isTextBlock = text.startsWith('"""', index);
      index = skipJavaQuoted(text, index, isTextBlock ? '"""' : '"', isTextBlock);
      push('STR', start);
      continue;
    }
    if (code === 39 /* ' */) {
      const start = index;
      index = skipJavaQuoted(text, index, "'", false);
      push('STR', start);
      continue;
    }
    if (isAsciiDigit(code)) {
      const start = index;
      index = scanJavaNumber(text, start);
      push('NUM', start);
      continue;
    }
    if (isJavaIdentifierStart(code)) {
      const start = index;
      index += 1;
      while (index < length && isJavaIdentifierPart(text.charCodeAt(index))) index += 1;
      const word = text.slice(start, index);
      push(JAVA_KEYWORDS.has(word) ? word : 'IDENT', start);
      continue;
    }
    const operator = JAVA_OPERATORS_BY_FIRST.get(text[index] ?? '')?.find((candidate) =>
      text.startsWith(candidate, index),
    );
    if (operator !== undefined) {
      push(operator, index);
      index += operator.length;
      continue;
    }
    // An unrecognized byte must never stall the scan.
    index += 1;
  }
  return tokens;
}

/** Tokenize one supported source file with its own language's tokenizer. */
function tokenizeSource(text: string, language: CloneLanguage): NormalizedToken[] {
  return language === 'java' ? tokenizeJava(text) : tokenizeTypeScript(text);
}

function buildIndexedFile(relPath: string, text: string, language: CloneLanguage): IndexedFile {
  return { relPath, language, text, lineStarts: computeLineStarts(text), tokens: tokenizeSource(text, language) };
}

async function readSeedFile(
  root: string,
  relPath: string,
  language: CloneLanguage,
): Promise<IndexedFile | CloneSeedSkipReason> {
  let real: string;
  try {
    real = await fs.realpath(path.resolve(root, relPath));
  } catch {
    return 'seed_file_missing';
  }
  if (!isInside(root, real)) return 'seed_path_outside_repository';
  try {
    if (!(await fs.stat(real)).isFile()) return 'seed_path_not_regular_file';
    return buildIndexedFile(
      path.relative(root, real).split(path.sep).join('/'),
      await fs.readFile(real, 'utf8'),
      language,
    );
  } catch {
    return 'seed_unreadable';
  }
}

/**
 * Pick the token that best represents the recorded line. Call-shaped identifiers are preferred,
 * then identifiers, then any token; ties go to the rarest token in the file and finally to the
 * earliest index, which keeps the choice deterministic.
 */
function chooseAnchorToken(
  tokens: readonly NormalizedToken[],
  recordedLine: number,
  widenLines: number,
): number | undefined {
  let candidates: number[] = [];
  for (let widen = 0; widen <= widenLines && !candidates.length; widen++) {
    const lines = widen === 0 ? new Set([recordedLine]) : new Set([recordedLine - widen, recordedLine + widen]);
    candidates = tokens.flatMap((token, index) => (lines.has(token.line) ? [index] : []));
  }
  if (!candidates.length) return undefined;
  const frequency = new Map<string, number>();
  for (const token of tokens) frequency.set(token.norm, (frequency.get(token.norm) ?? 0) + 1);
  let best: { index: number; score: number; frequency: number } | undefined;
  for (const index of candidates) {
    const token = tokens[index];
    if (token === undefined) continue;
    const callShaped = tokens[index + 1]?.norm === '(' && tokens[index - 1]?.norm === '.';
    const count = frequency.get(token.norm) ?? 0;
    const score = (callShaped ? 2 : 0) + (token.norm === 'IDENT' ? 1 : 0) + (count === 1 ? 0.5 : 0);
    if (
      best === undefined ||
      score > best.score ||
      (score === best.score && count < best.frequency) ||
      (score === best.score && count === best.frequency && index < best.index)
    ) {
      best = { index, score, frequency: count };
    }
  }
  return best?.index;
}

/** Center a contiguous token window of the target size on the anchor, clamped to the file. */
function extractSeedWindow(
  tokenCount: number,
  anchor: number,
  target: number,
): { startToken: number; endToken: number } {
  const half = Math.floor(target / 2);
  let startToken = anchor - half;
  let endToken = startToken + target;
  if (startToken < 0) {
    startToken = 0;
    endToken = Math.min(tokenCount, target);
  }
  if (endToken > tokenCount) {
    endToken = tokenCount;
    startToken = Math.max(0, endToken - target);
  }
  return { startToken, endToken };
}

function hashKgram(ids: Int32Array, offset: number, k: number): number {
  let hash = 2166136261 >>> 0;
  for (let index = 0; index < k; index++) {
    hash ^= ids[offset + index] ?? 0;
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash >>> 0;
}

function internFileTokens(file: IndexedFile, interned: Map<string, number>): Int32Array {
  const ids = new Int32Array(file.tokens.length);
  for (let index = 0; index < file.tokens.length; index++) {
    const norm = file.tokens[index]?.norm ?? '';
    let id = interned.get(norm);
    if (id === undefined) {
      id = interned.size + 1;
      interned.set(norm, id);
    }
    ids[index] = id;
  }
  return ids;
}

function countInSorted(values: Uint32Array, target: number): number {
  let low = 0;
  let high = values.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if ((values[mid] ?? 0) < target) low = mid + 1;
    else high = mid;
  }
  const first = low;
  high = values.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if ((values[mid] ?? 0) <= target) low = mid + 1;
    else high = mid;
  }
  return low - first;
}

/** Longest common subsequence over interned token ids, returning the matched index pairs. */
function lcsPairs(a: Int32Array, b: Int32Array): Array<[number, number]> {
  const columns = b.length + 1;
  const table = new Int32Array((a.length + 1) * columns);
  for (let i = 1; i <= a.length; i++) {
    const left = a[i - 1] ?? 0;
    for (let j = 1; j <= b.length; j++) {
      const diagonal = left === (b[j - 1] ?? -1) ? (table[(i - 1) * columns + (j - 1)] ?? 0) + 1 : 0;
      table[i * columns + j] = Math.max(diagonal, table[(i - 1) * columns + j] ?? 0, table[i * columns + (j - 1)] ?? 0);
    }
  }
  const pairs: Array<[number, number]> = [];
  let i = a.length;
  let j = b.length;
  while (i > 0 && j > 0) {
    if ((a[i - 1] ?? 0) === (b[j - 1] ?? -1)) {
      pairs.push([i - 1, j - 1]);
      i--;
      j--;
    } else if ((table[(i - 1) * columns + j] ?? 0) >= (table[i * columns + (j - 1)] ?? 0)) {
      i--;
    } else {
      j--;
    }
  }
  return pairs.reverse();
}

function excerptForLine(file: IndexedFile, line: number, maxLength: number): string {
  const start = file.lineStarts[line - 1];
  if (start === undefined) return '';
  return file.text
    .slice(start, file.lineStarts[line] ?? file.text.length)
    .trim()
    .slice(0, maxLength);
}

async function indexCorpus(
  root: string,
  cache: Map<string, IndexedFile>,
  options: CloneSearchOptions,
  languages: ReadonlySet<CloneLanguage>,
): Promise<IndexedCorpus> {
  const files: IndexedFile[] = [];
  const windows: TokenWindow[] = [];
  const inverted = new Map<number, number[]>();
  const idsByPath = new Map<string, Int32Array>();
  const interned = new Map<string, number>();
  let totalTokens = 0;
  let skippedFiles = 0;
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
      const language = cloneLanguageForPath(entry.name);
      if (language === undefined || !languages.has(language)) continue;
      if (
        files.length >= options.maxFiles ||
        totalTokens >= options.maxTotalTokens ||
        windows.length >= options.maxWindows
      ) {
        truncated = true;
        exhausted = true;
        break;
      }
      const relPath = path.relative(root, absolute).split(path.sep).join('/');
      let file = cache.get(relPath);
      if (file === undefined) {
        try {
          const stats = await fs.stat(absolute);
          if (stats.size > options.maxFileBytes) {
            skippedFiles++;
            truncated = true;
            continue;
          }
          file = buildIndexedFile(relPath, await fs.readFile(absolute, 'utf8'), language);
          cache.set(relPath, file);
        } catch {
          skippedFiles++;
          continue;
        }
      }
      const fileIndex = files.length;
      files.push(file);
      totalTokens += file.tokens.length;
      const ids = internFileTokens(file, interned);
      idsByPath.set(file.relPath, ids);
      const k = options.kGram;
      const tokenCount = file.tokens.length;
      const starts: number[] = [];
      for (let start = 0; start <= tokenCount - options.windowMinTokens; start += options.windowStepTokens) {
        starts.push(start);
      }
      const tailStart = Math.max(0, tokenCount - options.windowMaxTokens);
      if (!starts.includes(tailStart)) starts.push(tailStart);
      for (const start of starts) {
        if (windows.length >= options.maxWindows) {
          truncated = true;
          exhausted = true;
          break;
        }
        const end = Math.min(start + options.windowMaxTokens, tokenCount);
        if (end - start < Math.min(options.windowMinTokens, tokenCount) || end - start < k) continue;
        const kgrams = new Uint32Array(end - start - k + 1);
        for (let offset = 0; offset < kgrams.length; offset++) kgrams[offset] = hashKgram(ids, start + offset, k);
        kgrams.sort();
        const windowId = windows.length;
        windows.push({ fileIndex, startToken: start, endToken: end, kgrams });
        let previous = -1;
        for (const kgram of kgrams) {
          if (kgram === previous) continue;
          previous = kgram;
          const list = inverted.get(kgram);
          if (list === undefined) inverted.set(kgram, [windowId]);
          else list.push(windowId);
        }
      }
      if (exhausted) break;
    }
    if (exhausted) break;
  }

  return { files, windows, inverted, idsByPath, interned, totalTokens, skippedFiles, truncated };
}

/**
 * Rank windows by how much of the seed's k-gram multiset they contain. The score is a
 * containment ratio (multiset intersection over the seed's own k-grams), which is stable when the
 * candidate window is much larger than the seed.
 */
function rankWindows(
  seedKgrams: Uint32Array,
  corpus: IndexedCorpus,
  options: CloneSearchOptions,
  seedLanguage: CloneLanguage,
): RankedCandidate[] {
  const shared = new Map<number, number>();
  let offset = 0;
  while (offset < seedKgrams.length) {
    const kgram = seedKgrams[offset] ?? 0;
    let end = offset + 1;
    while (end < seedKgrams.length && seedKgrams[end] === kgram) end++;
    const seedCount = end - offset;
    for (const windowId of corpus.inverted.get(kgram) ?? []) {
      const window = corpus.windows[windowId];
      if (window === undefined) continue;
      // A window of another language can share punctuation and keyword shapes without sharing
      // any meaning, so it is never a candidate for this seed.
      if (corpus.files[window.fileIndex]?.language !== seedLanguage) continue;
      const candidateCount = countInSorted(window.kgrams, kgram);
      if (candidateCount === 0) continue;
      shared.set(windowId, (shared.get(windowId) ?? 0) + Math.min(seedCount, candidateCount));
    }
    offset = end;
  }
  const ranked: RankedCandidate[] = [];
  for (const [windowId, overlap] of shared) {
    if (overlap < options.minSharedKgrams) continue;
    const score = overlap / seedKgrams.length;
    if (score < options.initialSimilarityThreshold) continue;
    ranked.push({ windowId, shared: overlap, score });
  }
  ranked.sort((left, right) => {
    if (right.score !== left.score) return right.score - left.score;
    if (right.shared !== left.shared) return right.shared - left.shared;
    const leftWindow = corpus.windows[left.windowId];
    const rightWindow = corpus.windows[right.windowId];
    if (leftWindow === undefined || rightWindow === undefined) return 0;
    const leftFile = corpus.files[leftWindow.fileIndex]?.relPath ?? '';
    const rightFile = corpus.files[rightWindow.fileIndex]?.relPath ?? '';
    if (leftFile !== rightFile) return leftFile < rightFile ? -1 : 1;
    return leftWindow.startToken - rightWindow.startToken;
  });
  // Collapse overlapping windows inside one file so a repeated block cannot consume the alignment
  // budget and starve distinct regions elsewhere in the repository. Order is already deterministic.
  const distinct: RankedCandidate[] = [];
  const keptWindows: Array<{ fileIndex: number; startToken: number; endToken: number }> = [];
  for (const candidate of ranked) {
    const window = corpus.windows[candidate.windowId];
    if (window === undefined) continue;
    const overlaps = keptWindows.some((kept) => {
      if (kept.fileIndex !== window.fileIndex) return false;
      const intersection = Math.min(kept.endToken, window.endToken) - Math.max(kept.startToken, window.startToken) + 1;
      if (intersection <= 0) return false;
      const smaller = Math.min(kept.endToken - kept.startToken, window.endToken - window.startToken) + 1;
      return intersection / smaller > 0.5;
    });
    if (overlaps) continue;
    keptWindows.push({ fileIndex: window.fileIndex, startToken: window.startToken, endToken: window.endToken });
    distinct.push(candidate);
    if (distinct.length >= options.alignmentCandidates) break;
  }
  return distinct;
}

/**
 * Align each ranked window with the seed and keep the windows whose recorded-line anchor lines up
 * with a real candidate token. `match_line` is that token's line, never a window or function head.
 */
function buildSeedMatches(
  prepared: PreparedSeed,
  ids: Int32Array,
  ranked: readonly RankedCandidate[],
  corpus: IndexedCorpus,
  options: CloneSearchOptions,
): { matches: CloneMatch[]; unaligned: number; considered: number } {
  const seedIds = ids.subarray(prepared.startToken, prepared.endToken);
  const anchorRelative = prepared.anchorToken - prepared.startToken;
  const minimumAligned = Math.max(1, Math.ceil(seedIds.length * options.minAlignedSeedRatio));
  const matches: CloneMatch[] = [];
  const keptRanges: Array<{ file: string; start: number; end: number }> = [];
  const keptLines = new Set<string>();
  let unaligned = 0;
  let considered = 0;

  for (const candidate of ranked) {
    if (matches.length >= options.maxMatchesPerSeed) break;
    const window = corpus.windows[candidate.windowId];
    if (window === undefined) continue;
    const file = corpus.files[window.fileIndex];
    const candidateIds = file === undefined ? undefined : corpus.idsByPath.get(file.relPath);
    if (file === undefined || candidateIds === undefined) continue;
    const overlapsSeed =
      file.relPath === prepared.file.relPath &&
      window.endToken > prepared.startToken &&
      window.startToken < prepared.endToken;
    if (overlapsSeed) continue;
    considered++;
    const pairs = lcsPairs(seedIds, candidateIds.subarray(window.startToken, window.endToken));
    const anchorPair = pairs.find(([seedIndex]) => seedIndex === anchorRelative);
    if (anchorPair === undefined || pairs.length < minimumAligned) {
      unaligned++;
      continue;
    }
    let firstCandidate = Number.POSITIVE_INFINITY;
    let lastCandidate = -1;
    for (const [, candidateIndex] of pairs) {
      if (candidateIndex < firstCandidate) firstCandidate = candidateIndex;
      if (candidateIndex > lastCandidate) lastCandidate = candidateIndex;
    }
    if (lastCandidate < 0 || !Number.isFinite(firstCandidate)) continue;
    const matchLine = file.tokens[window.startToken + (anchorPair[1] ?? 0)]?.line;
    if (matchLine === undefined) continue;
    const globalStart = window.startToken + firstCandidate;
    const globalEnd = window.startToken + lastCandidate;
    const overlapsKept = keptRanges.some((range) => {
      if (range.file !== file.relPath) return false;
      const intersection = Math.min(range.end, globalEnd) - Math.max(range.start, globalStart) + 1;
      if (intersection <= 0) return false;
      return intersection / (Math.max(range.end, globalEnd) - Math.min(range.start, globalStart) + 1) > 0.5;
    });
    const lineKey = `${file.relPath}:${String(matchLine)}`;
    if (overlapsKept || keptLines.has(lineKey)) continue;
    keptLines.add(lineKey);
    keptRanges.push({ file: file.relPath, start: globalStart, end: globalEnd });
    matches.push({
      finding_id: prepared.seed.findingId,
      vulnerability_class: prepared.seed.vulnerabilityClass,
      seed_file: prepared.seed.file,
      seed_line: prepared.seed.line,
      match_file: file.relPath,
      match_line: matchLine,
      candidate_start_line: file.tokens[globalStart]?.line ?? matchLine,
      candidate_end_line: file.tokens[globalEnd]?.line ?? matchLine,
      score: Math.round(candidate.score * 10_000) / 10_000,
      excerpt: excerptForLine(file, matchLine, options.maxExcerptLength),
    });
  }

  matches.sort((left, right) => {
    if (right.score !== left.score) return right.score - left.score;
    if (left.match_file !== right.match_file) return left.match_file < right.match_file ? -1 : 1;
    return left.match_line - right.match_line;
  });
  return { matches, unaligned, considered };
}

interface PreparedSeed {
  readonly seed: CloneSearchSeed;
  readonly file: IndexedFile;
  readonly startToken: number;
  readonly endToken: number;
  readonly anchorToken: number;
}

function skippedRecord(
  seed: CloneSearchSeed,
  reason: CloneSeedSkipReason,
  language?: CloneLanguage,
): CloneSeedRecord {
  return {
    finding_id: seed.findingId,
    vulnerability_class: seed.vulnerabilityClass,
    seed_file: seed.file,
    seed_line: seed.line,
    ...(language !== undefined && { language }),
    status: 'skipped',
    token_count: 0,
    seed_start_line: 0,
    seed_end_line: 0,
    anchor_line: 0,
    anchor_token: '',
    candidates_considered: 0,
    candidates_unaligned: 0,
    matched: 0,
    reason,
  };
}

/** Validate a seed's path, tokenize its file, and cut the seed window and anchor. */
async function prepareSeed(
  root: string,
  cache: Map<string, IndexedFile>,
  seed: CloneSearchSeed,
  options: CloneSearchOptions,
): Promise<{ prepared?: PreparedSeed; record: CloneSeedRecord }> {
  const language = cloneLanguageForPath(seed.file);
  if (!Number.isInteger(seed.line) || seed.line < 1)
    return { record: skippedRecord(seed, 'invalid_seed_line', language) };
  if (language === undefined) return { record: skippedRecord(seed, 'unsupported_language') };
  let file = cache.get(seed.file);
  if (file === undefined) {
    const loaded = await readSeedFile(root, seed.file, language);
    if (typeof loaded === 'string') return { record: skippedRecord(seed, loaded, language) };
    file = loaded;
    cache.set(loaded.relPath, loaded);
  }
  const anchorToken = chooseAnchorToken(file.tokens, seed.line, options.anchorWidenLines);
  const anchor = anchorToken === undefined ? undefined : file.tokens[anchorToken];
  if (anchorToken === undefined || anchor === undefined)
    return { record: skippedRecord(seed, 'no_anchor_token', language) };
  const target = Math.min(options.seedMaxTokens, Math.max(options.seedMinTokens, options.seedTargetTokens));
  const { startToken, endToken } = extractSeedWindow(file.tokens.length, anchorToken, target);
  if (endToken - startToken < options.minSeedTokens)
    return { record: skippedRecord(seed, 'seed_too_short', language) };
  return {
    prepared: { seed, file, startToken, endToken, anchorToken },
    record: {
      finding_id: seed.findingId,
      vulnerability_class: seed.vulnerabilityClass,
      seed_file: seed.file,
      seed_line: seed.line,
      language,
      status: 'eligible',
      token_count: endToken - startToken,
      seed_start_line: file.tokens[startToken]?.line ?? seed.line,
      seed_end_line: file.tokens[endToken - 1]?.line ?? seed.line,
      anchor_line: anchor.line,
      anchor_token: anchor.norm,
      candidates_considered: 0,
      candidates_unaligned: 0,
      matched: 0,
    },
  };
}

/**
 * Search the repository for Type-2/Type-3 clones of every record-verified sink location.
 * Returns the Expansion-facing result plus seed and coverage documents for diagnostics.
 */
export async function searchCloneCandidates(
  repoPath: string,
  seeds: readonly CloneSearchSeed[],
  overrides: Partial<CloneSearchOptions> = {},
): Promise<CloneSearchOutcome> {
  const options: CloneSearchOptions = { ...CLONE_SEARCH_DEFAULTS, ...overrides };
  const root = await fs.realpath(repoPath);
  const cache = new Map<string, IndexedFile>();
  const records: CloneSeedRecord[] = [];
  const preparedSeeds: Array<{ prepared: PreparedSeed; recordIndex: number }> = [];
  let truncated = false;

  for (const [index, seed] of seeds.entries()) {
    if (index >= options.maxSeeds) {
      records.push(skippedRecord(seed, 'seed_limit', cloneLanguageForPath(seed.file)));
      truncated = true;
      continue;
    }
    const { prepared, record } = await prepareSeed(root, cache, seed, options);
    records.push(record);
    if (prepared !== undefined) preparedSeeds.push({ prepared, recordIndex: records.length - 1 });
  }

  // Indexing is scoped to the languages this run actually needs, so a Java-only scan never reads,
  // tokenizes, or matches the repository's JavaScript frontend.
  const seedLanguages = new Set(preparedSeeds.map(({ prepared }) => prepared.file.language));
  const corpus = await indexCorpus(root, cache, options, seedLanguages);
  truncated = truncated || corpus.truncated;

  const matches: CloneMatch[] = [];
  const seedMatchesById = new Map<number, CloneMatch[]>();
  let unalignedCandidates = 0;
  for (const [index, entry] of preparedSeeds.entries()) {
    const { prepared, recordIndex } = entry;
    const ids = corpus.idsByPath.get(prepared.file.relPath) ?? internFileTokens(prepared.file, corpus.interned);
    corpus.idsByPath.set(prepared.file.relPath, ids);
    const seedIds = ids.subarray(prepared.startToken, prepared.endToken);
    const kgrams = new Uint32Array(Math.max(0, seedIds.length - options.kGram + 1));
    for (let offset = 0; offset < kgrams.length; offset++) kgrams[offset] = hashKgram(seedIds, offset, options.kGram);
    kgrams.sort();
    const ranked = rankWindows(kgrams, corpus, options, prepared.file.language);
    const built = buildSeedMatches(prepared, ids, ranked, corpus, options);
    unalignedCandidates += built.unaligned;
    seedMatchesById.set(index, built.matches);
    const record = records[recordIndex];
    if (record !== undefined) {
      records[recordIndex] = {
        ...record,
        candidates_considered: built.considered,
        candidates_unaligned: built.unaligned,
        matched: built.matches.length,
      };
    }
  }

  // Interleave matches across seeds so one broad seed cannot consume the global budget.
  const cursors = preparedSeeds.map(() => 0);
  for (;;) {
    let progressed = false;
    for (const [index] of preparedSeeds.entries()) {
      const list = seedMatchesById.get(index) ?? [];
      const cursor = cursors[index] ?? 0;
      if (cursor >= list.length) continue;
      cursors[index] = cursor + 1;
      progressed = true;
      const match = list[cursor];
      if (match === undefined) continue;
      if (matches.length >= options.maxTotalMatches) {
        truncated = true;
        break;
      }
      matches.push(match);
    }
    if (matches.length >= options.maxTotalMatches || !progressed) break;
  }
  if (preparedSeeds.some((_, index) => (seedMatchesById.get(index)?.length ?? 0) > (cursors[index] ?? 0)))
    truncated = true;

  const skipped = records.filter((record) => record.status === 'skipped');
  const eligible = records.filter((record) => record.status === 'eligible');
  const skipReasons: Record<string, number> = {};
  for (const record of skipped) {
    const reason = record.reason ?? 'unknown';
    skipReasons[reason] = (skipReasons[reason] ?? 0) + 1;
  }
  const summary = {
    seeds_total: records.length,
    seeds_eligible: eligible.length,
    seeds_skipped: skipped.length,
    indexed_files: corpus.files.length,
    indexed_tokens: corpus.totalTokens,
    indexed_windows: corpus.windows.length,
    skipped_files: corpus.skippedFiles,
    unaligned_candidates: unalignedCandidates,
    matched: matches.length,
    truncated,
  };
  return {
    result: {
      schema_version: 2,
      algorithm: 'normalized_token_clone_v1',
      matches,
      skipped_seeds: skipped,
      truncated,
      statistics: {
        seed_count: records.length,
        eligible_seed_count: eligible.length,
        candidate_count: matches.length,
      },
    },
    seeds: { schema_version: 2, algorithm: 'normalized_token_clone_v1', seeds: records, truncated },
    coverage: {
      schema_version: 2,
      algorithm: 'normalized_token_clone_v1',
      summary,
      skip_reasons: skipReasons,
      seeds: records,
    },
  };
}
