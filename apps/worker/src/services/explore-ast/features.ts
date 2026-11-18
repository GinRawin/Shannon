// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Structural features for one forest: node categories, typed parent-child edges, and depth-limited
 * rooted subtree shapes. Features keep hierarchy, grammar fields and child order, so two forests
 * with the same node histogram but different nesting produce different feature multisets. Nothing
 * here is a token sequence or an n-gram.
 */

import type { AstFeatureWeights, NormalizedAstNode } from './types.js';

export type FeatureKind = 'node' | 'edge' | 'shape2' | 'shape3' | 'context' | 'api';

/** Children included in one shape string before it is truncated with a `+n` suffix. */
const MAX_SHAPE_CHILDREN = 4;

export function featureKind(feature: string): FeatureKind {
  if (feature.startsWith('EDGE:')) return 'edge';
  if (feature.startsWith('SHAPE2:')) return 'shape2';
  if (feature.startsWith('SHAPE3:')) return 'shape3';
  if (feature.startsWith('CONTEXT:')) return 'context';
  if (feature.startsWith('API:')) return 'api';
  return 'node';
}

export function baseWeightFor(kind: FeatureKind, weights: AstFeatureWeights): number {
  switch (kind) {
    case 'node':
      return weights.node;
    case 'edge':
      return weights.edge;
    case 'shape2':
      return weights.shapeDepth2;
    case 'shape3':
      return weights.shapeDepth3;
    case 'context':
      return weights.context;
    case 'api':
      return weights.api;
  }
}

/** `TYPE` plus its bounded structural detail (operator/arity); never an identifier or literal. */
function headOf(node: NormalizedAstNode): string {
  return node.detail === undefined ? node.type : `${node.type}:${node.detail}`;
}

function shapeOf(node: NormalizedAstNode, depth: number): string {
  const head = headOf(node);
  if (depth <= 1 || node.children.length === 0) return head;
  const shown = node.children.slice(0, MAX_SHAPE_CHILDREN);
  const parts = shown.map((child) => {
    const field = child.field ?? '';
    return `${field}:${shapeOf(child, depth - 1)}`;
  });
  const extra = node.children.length - shown.length;
  if (extra > 0) parts.push(`+${extra}`);
  return `${head}(${parts.join(',')})`;
}

function bump(counts: Map<string, number>, feature: string): void {
  counts.set(feature, (counts.get(feature) ?? 0) + 1);
}

function visit(node: NormalizedAstNode, counts: Map<string, number>): void {
  bump(counts, `NODE:${headOf(node)}`);
  if (node.softLabel !== undefined) bump(counts, `API:${node.softLabel.toLowerCase()}`);
  for (const child of node.children) {
    bump(counts, `EDGE:${node.type}/${child.field ?? '-'}>${child.type}`);
  }
  bump(counts, `SHAPE2:${shapeOf(node, 2)}`);
  bump(counts, `SHAPE3:${shapeOf(node, 3)}`);
  for (const child of node.children) visit(child, counts);
}

export interface ForestFeatureInput {
  readonly root: NormalizedAstNode;
  readonly contextPath: readonly { readonly type: string; readonly field?: string | undefined }[];
}

/** Multiset of structural features for one forest, excluding the synthetic root node itself. */
export function extractFeatures(forest: ForestFeatureInput): Map<string, number> {
  const counts = new Map<string, number>();
  for (const child of forest.root.children) visit(child, counts);
  if (forest.contextPath.length === 0) {
    bump(counts, 'CONTEXT:TOP_LEVEL');
  } else {
    for (const entry of forest.contextPath) bump(counts, `CONTEXT:INSIDE_${entry.type}`);
    const chain = forest.contextPath.map((entry) =>
      entry.field === undefined ? entry.type : `${entry.type}@${entry.field}`,
    );
    bump(counts, `CONTEXT:PATH_${chain.join('>')}`);
  }
  return counts;
}
