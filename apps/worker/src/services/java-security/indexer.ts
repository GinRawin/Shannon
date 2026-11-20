// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * One-time structural index over a Java source snapshot.
 *
 * Every `.java` file is parsed at most once. The pass records method invocations, constructor
 * calls, annotations, method declarations, and the minimal import/field/local type hints needed
 * to reason about receivers and bounded constants. It deliberately does not build a data-flow
 * graph: anything it cannot prove is retained and evaluated (or not) at query time.
 *
 * Parsing reuses the Explore grammar loader but serializes every `parseSource` call behind a
 * process-wide mutex, because the shared Tree-sitter parser releases the previous tree on the
 * next parse. The extracted data is plain JSON; no native node outlives this module.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { parseSource } from '../explore-ast/parser.js';
import { toExpr } from './expr.js';
import type { FileIndexEntry, LocalDef, RawArg, RawSite } from './types.js';

type TsNode = import('web-tree-sitter').Node;

export const DEFAULT_EXCLUDED_DIRS: readonly string[] = [
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

export interface ScanOptions {
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly timeoutMs: number;
  readonly includedExtensions: readonly string[];
  readonly excludedDirs: readonly string[];
}

export interface ScannedFile {
  readonly absPath: string;
  readonly relPath: string;
  readonly sha256: string;
  readonly bytes: number;
}

export interface ScanResult {
  readonly files: readonly ScannedFile[];
  readonly skipped: number;
  readonly truncated: boolean;
  readonly warnings: readonly string[];
}

export interface IndexResult {
  readonly entries: readonly FileIndexEntry[];
  readonly parseErrors: number;
  readonly truncated: boolean;
  readonly warnings: readonly string[];
}

function collapse(text: string, max: number): string {
  const oneLine = text.replace(/\s+/g, ' ').trim();
  return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine;
}

function slash(relPath: string): string {
  return relPath.split(path.sep).join('/');
}

// --- Parse serialization -------------------------------------------------------------------

let parseChain: Promise<void> = Promise.resolve();

async function serializeParse<T>(fn: () => Promise<T>): Promise<T> {
  const previous = parseChain;
  let release!: () => void;
  parseChain = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous;
  try {
    return await fn();
  } finally {
    release();
  }
}

// --- Filesystem scan -----------------------------------------------------------------------

async function walk(
  root: string,
  dir: string,
  options: ScanOptions,
  out: ScannedFile[],
  state: { skipped: number; truncated: boolean },
): Promise<void> {
  let dirents: import('node:fs').Dirent[];
  try {
    dirents = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const dirent of dirents) {
    if (out.length >= options.maxFiles) {
      state.truncated = true;
      return;
    }
    const abs = path.join(dir, dirent.name);
    if (dirent.isSymbolicLink()) {
      // Do not follow symlinks: keeps the walk inside the authorized source root.
      continue;
    }
    if (dirent.isDirectory()) {
      if (options.excludedDirs.includes(dirent.name)) continue;
      await walk(root, abs, options, out, state);
      continue;
    }
    if (!dirent.isFile()) continue;
    const rel = slash(path.relative(root, abs));
    const ext = path.extname(dirent.name).toLowerCase();
    if (!options.includedExtensions.includes(ext)) continue;
    let stat: import('node:fs').Stats;
    try {
      stat = await fs.stat(abs);
    } catch {
      state.skipped += 1;
      continue;
    }
    if (stat.size > options.maxFileBytes) {
      state.skipped += 1;
      continue;
    }
    let content: Buffer;
    try {
      content = await fs.readFile(abs);
    } catch {
      state.skipped += 1;
      continue;
    }
    out.push({
      absPath: abs,
      relPath: rel,
      sha256: createHash('sha256').update(content).digest('hex'),
      bytes: content.length,
    });
  }
}

/** Walk the source root and collect eligible files with their content digests. */
export async function scanSourceFiles(root: string, options: ScanOptions): Promise<ScanResult> {
  const out: ScannedFile[] = [];
  const state = { skipped: 0, truncated: false };
  const startedAt = Date.now();
  const deadline = options.timeoutMs > 0 ? startedAt + options.timeoutMs : Number.POSITIVE_INFINITY;
  const timer = setInterval(() => {
    if (Date.now() > deadline) state.truncated = true;
  }, 250);
  try {
    await walk(root, root, options, out, state);
  } finally {
    clearInterval(timer);
  }
  if (Date.now() > deadline) state.truncated = true;
  const warnings: string[] = [];
  if (state.truncated) warnings.push('file scan reached its time or file-count budget; results may be incomplete');
  return { files: out, skipped: state.skipped, truncated: state.truncated, warnings };
}

// --- Tree walk -----------------------------------------------------------------------------

interface MutableLocal {
  line: number;
  declaredType?: string;
  expr?: import('./types.js').ExprNode;
  assignCount: number;
  branchAssign: boolean;
  isParameter?: boolean;
}

const CLASS_NODE_TYPES = new Set([
  'class_declaration',
  'interface_declaration',
  'enum_declaration',
  'record_declaration',
]);
const METHOD_NODE_TYPES = new Set(['method_declaration', 'constructor_declaration']);
const BRANCH_NODE_TYPES = new Set([
  'if_statement',
  'for_statement',
  'enhanced_for_statement',
  'while_statement',
  'do_statement',
  'switch_expression',
  'switch_statement',
  'try_statement',
  'catch_clause',
]);
const ANNOTATION_NODE_TYPES = new Set(['annotation', 'marker_annotation']);

function ownerRoot(node: TsNode): string | undefined {
  const object = node.childForFieldName('object');
  if (!object) return undefined;
  if (object.type === 'identifier') return object.text;
  if (object.type === 'object_creation_expression') return object.childForFieldName('type')?.text;
  if (object.type === 'method_invocation' || object.type === 'field_access') return ownerRootLike(object);
  return undefined;
}

function ownerRootLike(node: TsNode): string | undefined {
  if (node.type === 'identifier') return node.text;
  const object = node.childForFieldName('object');
  if (object) return ownerRootLike(object);
  return undefined;
}

function receiverShape(node: TsNode): RawSite['receiverShape'] {
  const object = node.childForFieldName('object');
  if (!object) return 'none';
  if (object.type === 'identifier') return 'identifier';
  if (object.type === 'object_creation_expression') return 'new';
  if (object.type === 'method_invocation' || object.type === 'field_access') {
    const root = ownerRootLike(object);
    if (root !== undefined && /^[A-Z]/.test(root)) return 'static_call';
    return 'chain';
  }
  return 'chain';
}

function extractArgs(node: TsNode): RawArg[] {
  const args = node.childForFieldName('arguments');
  if (!args) return [];
  return args.namedChildren
    .filter((child) => child.type !== 'comment')
    .map((child) => ({
      expr: toExpr(child),
      line: child.startPosition.row + 1,
      column: child.startPosition.column + 1,
      text: collapse(child.text, 200),
    }));
}

interface TreeState {
  imports: Map<string, string>;
  fields: Map<string, string>;
  locals: Map<string, Map<string, MutableLocal>>;
  sites: RawSite[];
  classStack: string[];
  methods: string[];
  branchDepth: number;
}

function currentSymbol(state: TreeState): string | undefined {
  const cls = state.classStack.join('.');
  const method = state.methods[state.methods.length - 1];
  if (cls && method) return `${cls}.${method}`;
  return cls || undefined;
}

function localBucket(state: TreeState, symbol: string): Map<string, MutableLocal> {
  let bucket = state.locals.get(symbol);
  if (bucket === undefined) {
    bucket = new Map();
    state.locals.set(symbol, bucket);
  }
  return bucket;
}

function handleImport(node: TsNode, state: TreeState): void {
  const text = collapse(node.text, 400);
  if (text.startsWith('import static')) return;
  const name = node.namedChildren.find((c) => c.type === 'scoped_identifier' || c.type === 'identifier');
  if (!name) return;
  const fq = name.text;
  if (fq.endsWith('.*')) {
    state.imports.set('*', fq.slice(0, -2));
    return;
  }
  const simple = fq.slice(fq.lastIndexOf('.') + 1);
  if (simple.length > 0) state.imports.set(simple, fq);
}

function handleVariableDeclaration(node: TsNode, state: TreeState, isField: boolean): void {
  const typeNode = node.childForFieldName('type');
  const typeText = typeNode?.text;
  for (const child of node.namedChildren) {
    if (child.type !== 'variable_declarator') continue;
    const nameNode = child.childForFieldName('name');
    if (!nameNode || nameNode.type !== 'identifier') continue;
    const name = nameNode.text;
    if (isField) {
      if (typeText !== undefined) state.fields.set(name, typeText);
      continue;
    }
    const symbol = currentSymbol(state);
    if (symbol === undefined) continue;
    const valueNode = child.childForFieldName('value');
    const bucket = localBucket(state, symbol);
    const existing = bucket.get(name);
    const declType = typeText ?? existing?.declaredType;
    bucket.set(name, {
      line: child.startPosition.row + 1,
      ...(declType !== undefined && { declaredType: declType }),
      ...(valueNode && { expr: toExpr(valueNode) }),
      assignCount: existing?.assignCount ?? (valueNode ? 1 : 0),
      branchAssign: existing?.branchAssign ?? state.branchDepth > 0,
    });
  }
}

function handleFormalParameters(node: TsNode, state: TreeState): void {
  const parameters = node.childForFieldName('parameters');
  if (!parameters) return;
  const symbol = currentSymbol(state);
  if (symbol === undefined) return;
  const bucket = localBucket(state, symbol);
  for (const parameter of parameters.namedChildren) {
    if (parameter.type !== 'formal_parameter' && parameter.type !== 'spread_parameter') continue;
    const typeNode = parameter.childForFieldName('type');
    const nameNode =
      parameter.childForFieldName('name') ?? parameter.namedChildren.find((c) => c.type === 'identifier');
    if (!nameNode || nameNode.type !== 'identifier') continue;
    const declaredType = typeNode?.text;
    const existing = bucket.get(nameNode.text);
    bucket.set(nameNode.text, {
      line: parameter.startPosition.row + 1,
      ...(declaredType !== undefined && { declaredType }),
      assignCount: existing?.assignCount ?? 0,
      branchAssign: false,
      isParameter: true,
    });
  }
}

function handleAssignment(node: TsNode, state: TreeState): void {
  const left = node.childForFieldName('left');
  if (!left || left.type !== 'identifier') return;
  const symbol = currentSymbol(state);
  if (symbol === undefined) return;
  const bucket = localBucket(state, symbol);
  const existing = bucket.get(left.text);
  const right = node.childForFieldName('right');
  if (existing === undefined) {
    bucket.set(left.text, {
      line: node.startPosition.row + 1,
      ...(right && { expr: toExpr(right) }),
      assignCount: 1,
      branchAssign: state.branchDepth > 0,
    });
    return;
  }
  existing.assignCount += 1;
  if (state.branchDepth > 0) existing.branchAssign = true;
}

function recordCall(node: TsNode, state: TreeState): void {
  const nameNode = node.childForFieldName('name');
  const object = node.childForFieldName('object');
  const symbol = currentSymbol(state);
  const root = ownerRoot(node);
  const shape = receiverShape(node);
  state.sites.push({
    kind: 'call',
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
    methodName: nameNode?.text ?? '',
    ...(object && { receiverText: collapse(object.text, 200) }),
    ...(root !== undefined && { receiverRoot: root }),
    ...(shape !== undefined && { receiverShape: shape }),
    argCount: node.childForFieldName('arguments')?.namedChildren.length ?? 0,
    args: extractArgs(node),
    code: collapse(node.text, 400),
    ...(symbol !== undefined && { symbol }),
  });
}

function recordConstructor(node: TsNode, state: TreeState): void {
  const typeNode = node.childForFieldName('type');
  const symbol = currentSymbol(state);
  state.sites.push({
    kind: 'constructor',
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
    typeName: typeNode?.text ?? '',
    argCount: node.childForFieldName('arguments')?.namedChildren.length ?? 0,
    args: extractArgs(node),
    code: collapse(node.text, 400),
    ...(symbol !== undefined && { symbol }),
  });
}

function recordAnnotation(node: TsNode, state: TreeState): void {
  const nameNode = node.childForFieldName('name');
  if (!nameNode) return;
  const symbol = currentSymbol(state);
  state.sites.push({
    kind: 'annotation',
    line: node.startPosition.row + 1,
    column: node.startPosition.column + 1,
    annotationName: nameNode.text,
    argCount: node.childForFieldName('arguments')?.namedChildren.length ?? 0,
    args: extractArgs(node),
    code: collapse(node.text, 300),
    ...(symbol !== undefined && { symbol }),
  });
}

function walkTree(node: TsNode, state: TreeState): void {
  const type = node.type;
  if (type === 'import_declaration') {
    handleImport(node, state);
    return;
  }
  if (CLASS_NODE_TYPES.has(type)) {
    const name = node.childForFieldName('name')?.text;
    state.classStack.push(name ?? '');
    for (const child of node.namedChildren) walkTree(child, state);
    state.classStack.pop();
    return;
  }
  if (METHOD_NODE_TYPES.has(type)) {
    const name = node.childForFieldName('name')?.text ?? '';
    state.methods.push(name);
    const symbol = currentSymbol(state);
    state.sites.push({
      kind: 'method_declaration',
      line: node.startPosition.row + 1,
      column: node.startPosition.column + 1,
      methodName: name,
      argCount: node.childForFieldName('parameters')?.namedChildren.length ?? 0,
      args: [],
      code: collapse(node.text, 200),
      ...(symbol !== undefined && { symbol }),
    });
    handleFormalParameters(node, state);
    for (const child of node.namedChildren) walkTree(child, state);
    state.methods.pop();
    return;
  }
  if (type === 'field_declaration') {
    handleVariableDeclaration(node, state, true);
  } else if (type === 'local_variable_declaration') {
    handleVariableDeclaration(node, state, false);
  } else if (type === 'assignment_expression') {
    handleAssignment(node, state);
  } else if (type === 'update_expression') {
    const argument = node.childForFieldName('argument');
    const symbol = currentSymbol(state);
    if (argument?.type === 'identifier' && symbol !== undefined) {
      const existing = localBucket(state, symbol).get(argument.text);
      if (existing) {
        existing.assignCount += 1;
        if (state.branchDepth > 0) existing.branchAssign = true;
      }
    }
  } else if (type === 'method_invocation') {
    recordCall(node, state);
  } else if (type === 'object_creation_expression') {
    recordConstructor(node, state);
  } else if (ANNOTATION_NODE_TYPES.has(type)) {
    recordAnnotation(node, state);
  }

  const branches = BRANCH_NODE_TYPES.has(type);
  if (branches) state.branchDepth += 1;
  for (const child of node.namedChildren) walkTree(child, state);
  if (branches) state.branchDepth -= 1;
}

function toLocalDef(local: MutableLocal): LocalDef {
  return {
    line: local.line,
    ...(local.declaredType !== undefined && { declaredType: local.declaredType }),
    ...(local.expr !== undefined && { expr: local.expr }),
    reassigned: local.assignCount > 1,
    inBranch: local.branchAssign,
    ...(local.isParameter === true && { isParameter: true }),
  };
}

function extractEntry(relPath: string, sha256: string, root: TsNode, parseError: boolean): FileIndexEntry {
  const state: TreeState = {
    imports: new Map(),
    fields: new Map(),
    locals: new Map(),
    sites: [],
    classStack: [],
    methods: [],
    branchDepth: 0,
  };
  walkTree(root, state);
  state.sites.sort((a, b) => a.line - b.line || a.column - b.column);
  const locals: Record<string, Record<string, LocalDef>> = {};
  for (const [symbol, bucket] of state.locals) {
    const obj: Record<string, LocalDef> = {};
    for (const [name, def] of bucket) obj[name] = toLocalDef(def);
    locals[symbol] = obj;
  }
  return {
    path: relPath,
    sha256,
    imports: Object.fromEntries(state.imports),
    fields: Object.fromEntries(state.fields),
    locals,
    sites: state.sites,
    parseError,
  };
}

/** Parse each scanned Java file exactly once and extract its structural index entry. */
export async function indexFiles(
  sourceDir: string,
  files: readonly ScannedFile[],
  options: { readonly timeoutMs: number },
): Promise<IndexResult> {
  const entries: FileIndexEntry[] = [];
  const warnings: string[] = [];
  let parseErrors = 0;
  let truncated = false;
  const deadline = options.timeoutMs > 0 ? Date.now() + options.timeoutMs : Number.POSITIVE_INFINITY;

  for (const file of files) {
    if (Date.now() > deadline) {
      truncated = true;
      warnings.push('AST indexing reached its time budget; results may be incomplete');
      break;
    }
    const ext = path.extname(file.relPath).toLowerCase();
    if (ext !== '.java') continue;
    try {
      const content = await fs.readFile(file.absPath, 'utf8');
      const parsed = await serializeParse(() => parseSource('java', content));
      const entry = extractEntry(file.relPath, file.sha256, parsed.root, parsed.hasError);
      if (parsed.hasError) {
        parseErrors += 1;
        warnings.push(`failed to parse ${file.relPath}`);
      }
      entries.push(entry);
    } catch (error) {
      parseErrors += 1;
      warnings.push(`failed to parse ${file.relPath}`);
      entries.push({
        path: file.relPath,
        sha256: file.sha256,
        imports: {},
        fields: {},
        locals: {},
        sites: [],
        parseError: true,
      });
      void error;
    }
  }

  void sourceDir;
  return { entries, parseErrors, truncated, warnings };
}
