// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Sink-anchored AST Forest construction.
 *
 * A seed is a recorded line, not a node: the recorder never tells us which call is the sink, so the
 * anchor is chosen from the executable statements that cover that line, and several alternatives
 * are kept when a single line holds multiple calls. The forest is then the anchor statement plus a
 * small, symmetric window of its sibling statements inside the same block, never crossing a
 * function boundary, with the enclosing control context recorded separately.
 */

import type { AstContextEntry, AstForest, AstNodeCategory, NormalizedAstNode } from './types.js';

/** Anchor preference order when several nodes cover the recorded line. */
const ANCHOR_PRIORITY: ReadonlyMap<AstNodeCategory, number> = new Map<AstNodeCategory, number>([
  ['CALL', 0],
  ['ASSIGNMENT', 1],
  ['RETURN', 2],
  ['DECLARATION', 3],
  ['AWAIT', 4],
]);

/** Control structures that keep their meaning in `contextPath` and the change flag. */
const CONTROL_CONTEXTS: ReadonlySet<AstNodeCategory> = new Set<AstNodeCategory>(['IF', 'LOOP', 'TRY', 'LAMBDA']);

/** Types that can never be a standalone statement anchor even if they cover the line. */
const NON_ANCHOR_TYPES: ReadonlySet<AstNodeCategory> = new Set<AstNodeCategory>([
  'FOREST',
  'BLOCK',
  'IDENTIFIER',
  'LITERAL',
  'MEMBER_ACCESS',
  'INDEX_ACCESS',
  'BINARY_OP',
  'UNARY_OP',
  'OTHER',
]);

function isStatementContainer(node: NormalizedAstNode): boolean {
  return node.type === 'BLOCK' || node.id === -1;
}

function nodeById(
  forestNodes: readonly NormalizedAstNode[],
  root: NormalizedAstNode,
  id: number,
): NormalizedAstNode | undefined {
  if (id === -1) return root;
  if (id < 0) return undefined;
  return forestNodes[id];
}

/** Number of nodes in a subtree, including the root. */
export function subtreeSize(node: NormalizedAstNode): number {
  let total = 1;
  const stack = [...node.children];
  while (stack.length) {
    const current = stack.pop();
    if (current === undefined) break;
    total++;
    stack.push(...current.children);
  }
  return total;
}

/** Collect the node ids of a subtree, including the root, in pre-order. */
export function subtreeIds(node: NormalizedAstNode): number[] {
  const ids: number[] = [node.id];
  for (const child of node.children) ids.push(...subtreeIds(child));
  return ids;
}

function coversLine(node: NormalizedAstNode, line: number): boolean {
  return node.startLine <= line && line <= node.endLine;
}

function spanLength(node: NormalizedAstNode): number {
  return node.endByte - node.startByte;
}

export interface AnchorSearchResult {
  readonly anchors: readonly NormalizedAstNode[];
  /** Recorded line had no statement; the match came from a nearby executable line. */
  readonly widened: boolean;
  /** More than one equally-specific anchor covered the line. */
  readonly ambiguous: boolean;
}

/**
 * Anchor nodes for a recorded line, ordered by specificity. Preferred call/assignment/return
 * statements win, and any outer node that merely contains a selected inner node is skipped, so a
 * normal call line yields exactly one anchor. When several sibling statements start on the line
 * (for example `audit(x); db.query(y);`) all of them are returned, so no single call is guessed as
 * the sink.
 */
export function findAnchorNodes(
  nodes: readonly NormalizedAstNode[],
  recordedLine: number,
  widenLines: number,
  maxAlternatives: number,
): AnchorSearchResult {
  for (let widen = 0; widen <= widenLines; widen++) {
    const lines = widen === 0 ? [recordedLine] : [recordedLine - widen, recordedLine + widen];
    const candidates: NormalizedAstNode[] = [];
    for (const node of nodes) {
      if (node.id < 0 || NON_ANCHOR_TYPES.has(node.type)) continue;
      if (!ANCHOR_PRIORITY.has(node.type)) continue;
      if (lines.some((line) => line >= 1 && coversLine(node, line))) candidates.push(node);
    }
    if (!candidates.length) continue;
    candidates.sort((left, right) => {
      const byPriority = (ANCHOR_PRIORITY.get(left.type) ?? 9) - (ANCHOR_PRIORITY.get(right.type) ?? 9);
      if (byPriority !== 0) return byPriority;
      const bySpan = spanLength(left) - spanLength(right);
      if (bySpan !== 0) return bySpan;
      return left.startByte - right.startByte;
    });
    const selected: NormalizedAstNode[] = [];
    for (const node of candidates) {
      // Prefer the innermost node: an anchor that merely wraps an already-selected anchor is skipped.
      if (selected.some((chosen) => contains(chosen, node))) continue;
      selected.push(node);
      if (selected.length >= Math.max(1, maxAlternatives)) break;
    }
    if (selected.length) return { anchors: selected, widened: widen > 0, ambiguous: selected.length > 1 };
  }
  return { anchors: [], widened: false, ambiguous: false };
}

function contains(outer: NormalizedAstNode, inner: NormalizedAstNode): boolean {
  if (outer.id === inner.id) return false;
  return outer.startByte <= inner.startByte && inner.endByte <= outer.endByte;
}

/** The primary anchor of a candidate statement: its innermost call/assignment/return, or itself. */
export function primaryAnchor(statement: NormalizedAstNode): NormalizedAstNode {
  const results = findAnchorNodes(subtreeNodes(statement), statement.startLine, 0, 1);
  return results.anchors[0] ?? statement;
}

function subtreeNodes(root: NormalizedAstNode): NormalizedAstNode[] {
  const out: NormalizedAstNode[] = [root];
  for (const child of root.children) out.push(...subtreeNodes(child));
  return out;
}

/** Enumerate statement-level nodes: every direct child of a block or of the file root. */
export function statementUnits(root: NormalizedAstNode): NormalizedAstNode[] {
  const units: NormalizedAstNode[] = [];
  const visit = (node: NormalizedAstNode): void => {
    if (isStatementContainer(node)) {
      for (const child of node.children) {
        if (child.type === 'IDENTIFIER' || child.type === 'LITERAL') continue;
        units.push(child);
      }
    }
    for (const child of node.children) visit(child);
  };
  visit(root);
  return units;
}

function contextFor(
  nodes: readonly NormalizedAstNode[],
  root: NormalizedAstNode,
  statement: NormalizedAstNode,
  maxDepth: number,
): AstContextEntry[] {
  const path: AstContextEntry[] = [];
  let childField = statement.field;
  let current = nodeById(nodes, root, statement.parentId);
  while (current !== undefined && current.id >= 0 && path.length < maxDepth) {
    if (CONTROL_CONTEXTS.has(current.type)) path.push({ type: current.type, field: childField });
    childField = current.field;
    current = nodeById(nodes, root, current.parentId);
  }
  return path;
}

/** The statement-level ancestor of a node: its nearest ancestor that sits inside a block/root. */
function statementAncestor(
  nodes: readonly NormalizedAstNode[],
  root: NormalizedAstNode,
  anchor: NormalizedAstNode,
): NormalizedAstNode {
  let current = anchor;
  for (;;) {
    const parent = nodeById(nodes, root, current.parentId);
    if (parent === undefined) return current;
    if (isStatementContainer(parent)) return current;
    current = parent;
  }
}

export interface ForestBuildResult {
  readonly forest?: AstForest | undefined;
  readonly reason?: 'forest_too_small' | undefined;
}

/** Build the local forest around one anchor node, never crossing the enclosing block. */
export function buildForest(
  language: AstForest['language'],
  file: string,
  root: NormalizedAstNode,
  nodes: readonly NormalizedAstNode[],
  anchor: NormalizedAstNode,
  options: { siblingRadius: number; maxAncestorDepth: number; minForestNodes: number; maxForestNodes: number },
): ForestBuildResult {
  const statement = statementAncestor(nodes, root, anchor);
  const containerNode = nodeById(nodes, root, statement.parentId);
  const siblings = containerNode === undefined ? [statement] : containerNode.children;
  const index = siblings.findIndex((node) => node.id === statement.id);
  const radius = options.siblingRadius;
  const from = Math.max(0, (index < 0 ? 0 : index) - radius);
  const to = Math.min(siblings.length, (index < 0 ? 1 : index) + radius + 1);
  let window = siblings.slice(from, to);

  // Trim whole statements from the outside until the forest fits, always keeping the anchor.
  const sizeOf = (list: readonly NormalizedAstNode[]): number => list.reduce((sum, node) => sum + subtreeSize(node), 0);
  while (window.length > 1 && sizeOf(window) > options.maxForestNodes) {
    const first = window[0];
    const last = window[window.length - 1];
    if (first === undefined || last === undefined) break;
    if (first.id === statement.id) window = window.slice(0, window.length - 1);
    else if (last.id === statement.id) window = window.slice(1);
    else window = window.slice(1, window.length - 1);
  }

  const nodeCount = sizeOf(window);
  if (nodeCount < options.minForestNodes) return { reason: 'forest_too_small' };

  const startLine = window.reduce((min, node) => Math.min(min, node.startLine), Number.MAX_SAFE_INTEGER);
  const endLine = window.reduce((max, node) => Math.max(max, node.endLine), 0);
  const synthetic: NormalizedAstNode = {
    id: -1,
    type: 'FOREST',
    field: undefined,
    detail: undefined,
    softLabel: undefined,
    parentId: -1,
    children: [...window],
    startByte: window.reduce((min, node) => Math.min(min, node.startByte), Number.MAX_SAFE_INTEGER),
    endByte: window.reduce((max, node) => Math.max(max, node.endByte), 0),
    startLine,
    endLine,
  };

  return {
    forest: {
      language,
      file,
      root: synthetic,
      nodes,
      anchorNodeId: anchor.id,
      anchorStatementId: statement.id,
      anchorLine: anchor.startLine,
      contextPath: contextFor(nodes, root, statement, options.maxAncestorDepth),
      startLine,
      endLine,
      nodeCount,
    },
  };
}

/** True when the control context chain differs (types only, fields ignored). */
export function contextChanged(seed: AstForest, candidate: AstForest): boolean {
  const left = seed.contextPath.map((entry) => entry.type).join('>');
  const right = candidate.contextPath.map((entry) => entry.type).join('>');
  return left !== right;
}

/**
 * Clone a forest so it owns only the nodes inside its own window. Candidate forests reference a
 * shared per-file node array; compacting lets that array be released once the file is scanned, which
 * keeps memory proportional to the number of forests rather than the whole repository.
 */
export function compactForest(forest: AstForest): AstForest {
  const nodes: NormalizedAstNode[] = [];
  const idMap = new Map<number, number>();
  const copy = (node: NormalizedAstNode, parentId: number): NormalizedAstNode => {
    const id = nodes.length;
    idMap.set(node.id, id);
    const cloned: NormalizedAstNode = {
      id,
      type: node.type,
      field: node.field,
      detail: node.detail,
      softLabel: node.softLabel,
      parentId,
      children: [],
      startByte: node.startByte,
      endByte: node.endByte,
      startLine: node.startLine,
      endLine: node.endLine,
    };
    nodes.push(cloned);
    cloned.children.push(...node.children.map((child) => copy(child, id)));
    return cloned;
  };
  const children = forest.root.children.map((child) => copy(child, -1));
  const anchorNodeId = idMap.get(forest.anchorNodeId) ?? forest.anchorNodeId;
  const anchorStatementId = idMap.get(forest.anchorStatementId) ?? forest.anchorStatementId;
  return {
    ...forest,
    root: { ...forest.root, children },
    nodes,
    anchorNodeId,
    anchorStatementId,
  };
}

/** Nodes of the anchor statement subtree, used to verify where the anchor mapped. */
export function anchorStatementIds(forest: AstForest): Set<number> {
  const statement = nodeById(forest.nodes, forest.root, forest.anchorStatementId);
  if (statement === undefined) return new Set<number>();
  return new Set(subtreeIds(statement));
}
