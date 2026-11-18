// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Ordered tree/forest approximate matching.
 *
 * This is the Type-3 core: it aligns two Sink-anchored forests as ordered, typed trees, allowing a
 * whole statement subtree to be inserted or deleted for a bounded cost, substituting a node for a
 * dissimilar node at a high cost, and never reordering children. The seed anchor is constrained:
 * a candidate is only accepted when the seed anchor maps onto the candidate's own anchor statement,
 * which is what makes the reported `match_line` trustworthy.
 */

import { anchorStatementIds, contextChanged, subtreeSize } from './forest.js';
import type { AstForest, AstMatchEvidence, AstNodeCategory, NormalizedAstNode } from './types.js';

/** Same-type nodes with a different operator/arity cost this much. */
const DETAIL_MISMATCH = 0.25;
/** Identifier <-> literal is the cheapest possible non-identical substitution. */
const LEAF_MISMATCH = 0.1;
/** Different types in the same structural family cost this much. */
const FAMILY_MISMATCH = 1.2;
/** Unrelated types (e.g. `CALL` vs `RETURN`) cost this much. */
const TYPE_MISMATCH = 3;
/** Fixed overhead for inserting or deleting a whole subtree. */
const SUBTREE_BASE = 1;
/** Marginal cost per node of an inserted/deleted subtree, so a long log branch is tolerable. */
const SUBTREE_PER_NODE = 0.6;

const FAMILY: Readonly<Partial<Record<AstNodeCategory, string>>> = Object.freeze({
  FOREST: 'block',
  BLOCK: 'block',
  OTHER: 'block',
  DECLARATION: 'decl',
  LAMBDA: 'decl',
  ASSIGNMENT: 'arith',
  BINARY_OP: 'arith',
  UNARY_OP: 'arith',
  CALL: 'call',
  IF: 'control',
  LOOP: 'control',
  TRY: 'control',
  RETURN: 'flow',
  AWAIT: 'flow',
  MEMBER_ACCESS: 'access',
  INDEX_ACCESS: 'access',
  IDENTIFIER: 'leaf',
  LITERAL: 'leaf',
});

function substitutionCost(left: NormalizedAstNode, right: NormalizedAstNode): number {
  if (left.type === right.type) return left.detail === right.detail ? 0 : DETAIL_MISMATCH;
  const leftFamily = FAMILY[left.type];
  const rightFamily = FAMILY[right.type];
  if (leftFamily === 'leaf' && rightFamily === 'leaf') return LEAF_MISMATCH;
  if (leftFamily !== undefined && leftFamily === rightFamily) return FAMILY_MISMATCH;
  return TYPE_MISMATCH;
}

function subtreeCost(node: NormalizedAstNode): number {
  return SUBTREE_BASE + SUBTREE_PER_NODE * subtreeSize(node);
}

interface Reconstruction {
  readonly mappings: Map<number, number>;
  insertedSubtrees: number;
  deletedSubtrees: number;
  mappedNodes: number;
}

class OrderedMatcher {
  private readonly memo = new Map<string, number>();
  private cells = 0;
  private exceeded = false;

  constructor(private readonly maxCells: number) {}

  get budgetExceeded(): boolean {
    return this.exceeded;
  }

  /** DP cells consumed so far, used by the caller to enforce a per-seed operations budget. */
  get operations(): number {
    return this.cells;
  }

  /** Cost of aligning the two synthetic forest roots (their statement sequences). */
  forestCost(seed: AstForest, candidate: AstForest): number {
    return this.sequenceCost(seed.root.children, candidate.root.children);
  }

  /** Memoized cost of aligning node `left` onto node `right` (including their child sequences). */
  treeCost(left: NormalizedAstNode, right: NormalizedAstNode): number {
    const key = `${left.id}:${right.id}`;
    const cached = this.memo.get(key);
    if (cached !== undefined) return cached;
    if (this.exceeded) return 0;
    const cost = substitutionCost(left, right) + this.sequenceCost(left.children, right.children);
    this.memo.set(key, cost);
    return cost;
  }

  /** Ordered edit distance over two child sequences; whole subtrees are the insert/delete unit. */
  private sequenceCost(left: readonly NormalizedAstNode[], right: readonly NormalizedAstNode[]): number {
    const rows = left.length;
    const columns = right.length;
    this.cells += (rows + 1) * (columns + 1);
    if (this.cells > this.maxCells) {
      this.exceeded = true;
      return 0;
    }
    let previous = new Float64Array(columns + 1);
    let current = new Float64Array(columns + 1);
    for (let column = 1; column <= columns; column++) {
      const node = right[column - 1];
      previous[column] = (previous[column - 1] ?? 0) + (node === undefined ? 0 : subtreeCost(node));
    }
    for (let row = 1; row <= rows; row++) {
      const leftNode = left[row - 1];
      current[0] = (previous[0] ?? 0) + (leftNode === undefined ? 0 : subtreeCost(leftNode));
      for (let column = 1; column <= columns; column++) {
        const rightNode = right[column - 1];
        if (leftNode === undefined || rightNode === undefined) continue;
        const match = (previous[column - 1] ?? 0) + this.treeCost(leftNode, rightNode);
        const remove = (previous[column] ?? 0) + subtreeCost(leftNode);
        const insert = (current[column - 1] ?? 0) + subtreeCost(rightNode);
        current[column] = Math.min(match, remove, insert);
      }
      const swap = previous;
      previous = current;
      current = swap;
    }
    return previous[columns] ?? 0;
  }

  /** Deterministic backtrack over the same DP, collecting node mappings and structural edits. */
  reconstruct(left: readonly NormalizedAstNode[], right: readonly NormalizedAstNode[], out: Reconstruction): void {
    const rows = left.length;
    const columns = right.length;
    const matrix: number[][] = [];
    for (let row = 0; row <= rows; row++) matrix.push(new Array<number>(columns + 1).fill(0));
    for (let column = 1; column <= columns; column++) {
      const node = right[column - 1];
      const rowZero = matrix[0];
      if (rowZero !== undefined) {
        rowZero[column] = (rowZero[column - 1] ?? 0) + (node === undefined ? 0 : subtreeCost(node));
      }
    }
    for (let row = 1; row <= rows; row++) {
      const leftNode = left[row - 1];
      const rowCells = matrix[row];
      const previousCells = matrix[row - 1];
      if (rowCells === undefined || previousCells === undefined) continue;
      rowCells[0] = (previousCells[0] ?? 0) + (leftNode === undefined ? 0 : subtreeCost(leftNode));
      for (let column = 1; column <= columns; column++) {
        const rightNode = right[column - 1];
        if (leftNode === undefined || rightNode === undefined) continue;
        const match = (previousCells[column - 1] ?? 0) + this.treeCost(leftNode, rightNode);
        const remove = (previousCells[column] ?? 0) + subtreeCost(leftNode);
        const insert = (rowCells[column - 1] ?? 0) + subtreeCost(rightNode);
        rowCells[column] = Math.min(match, remove, insert);
      }
    }

    let row = rows;
    let column = columns;
    while (row > 0 || column > 0) {
      const leftNode = row > 0 ? left[row - 1] : undefined;
      const rightNode = column > 0 ? right[column - 1] : undefined;
      const diagonal =
        leftNode !== undefined && rightNode !== undefined ? this.treeCost(leftNode, rightNode) : undefined;
      const matchCost =
        diagonal === undefined ? Number.POSITIVE_INFINITY : (matrix[row - 1]?.[column - 1] ?? 0) + diagonal;
      const removeCost =
        leftNode === undefined ? Number.POSITIVE_INFINITY : (matrix[row - 1]?.[column] ?? 0) + subtreeCost(leftNode);
      const insertCost =
        rightNode === undefined ? Number.POSITIVE_INFINITY : (matrix[row]?.[column - 1] ?? 0) + subtreeCost(rightNode);
      const best = Math.min(matchCost, removeCost, insertCost);
      if (leftNode !== undefined && rightNode !== undefined && matchCost === best) {
        out.mappedNodes++;
        out.mappings.set(leftNode.id, rightNode.id);
        this.reconstruct(leftNode.children, rightNode.children, out);
        row--;
        column--;
      } else if (leftNode !== undefined && removeCost === best) {
        out.deletedSubtrees++;
        row--;
      } else if (rightNode !== undefined) {
        out.insertedSubtrees++;
        column--;
      } else {
        break;
      }
    }
  }
}

export interface MatchOutcome {
  readonly similarity: number;
  readonly evidence: AstMatchEvidence;
  readonly budgetExceeded: boolean;
  readonly operations: number;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

/**
 * Align a seed forest with a candidate forest. When the seed anchor does not map onto the
 * candidate's anchor statement the result carries `anchor_mapped: false` and a zero similarity, and
 * the caller must not report a `match_line` for it.
 */
export function matchForests(seed: AstForest, candidate: AstForest, maxCells: number): MatchOutcome {
  const matcher = new OrderedMatcher(maxCells);
  const reconstruction: Reconstruction = {
    mappings: new Map<number, number>(),
    insertedSubtrees: 0,
    deletedSubtrees: 0,
    mappedNodes: 0,
  };
  // Prime the cost memo, then backtrack over the same alignments.
  const cost = matcher.forestCost(seed, candidate);
  if (matcher.budgetExceeded)
    return {
      similarity: 0,
      budgetExceeded: true,
      operations: matcher.operations,
      evidence: {
        retrieval_score: 0,
        tree_similarity: 0,
        anchor_confidence: 0,
        seed_nodes: seed.nodeCount,
        candidate_nodes: candidate.nodeCount,
        mapped_nodes: 0,
        inserted_subtrees: 0,
        deleted_subtrees: 0,
        control_context_changed: contextChanged(seed, candidate),
        anchor_mapped: false,
      },
    };
  matcher.reconstruct(seed.root.children, candidate.root.children, reconstruction);

  const budget = 2 * Math.max(seed.nodeCount, candidate.nodeCount, 1);
  const similarity = clamp01(1 - cost / budget);

  const mappedAnchorId = reconstruction.mappings.get(seed.anchorNodeId);
  const seedAnchor = seed.nodes[seed.anchorNodeId];
  let anchorConfidence = 0;
  if (mappedAnchorId !== undefined && seedAnchor !== undefined) {
    if (mappedAnchorId === candidate.anchorNodeId) anchorConfidence = 1;
    else {
      const mappedNode = candidate.nodes[mappedAnchorId];
      if (
        mappedNode !== undefined &&
        mappedNode.type === seedAnchor.type &&
        anchorStatementIds(candidate).has(mappedAnchorId)
      )
        anchorConfidence = 0.85;
    }
  }
  return {
    similarity: anchorConfidence > 0 ? similarity : 0,
    budgetExceeded: false,
    operations: matcher.operations,
    evidence: {
      retrieval_score: 0,
      tree_similarity: similarity,
      anchor_confidence: anchorConfidence,
      seed_nodes: seed.nodeCount,
      candidate_nodes: candidate.nodeCount,
      mapped_nodes: reconstruction.mappedNodes,
      inserted_subtrees: reconstruction.insertedSubtrees,
      deleted_subtrees: reconstruction.deletedSubtrees,
      control_context_changed: contextChanged(seed, candidate),
      anchor_mapped: anchorConfidence > 0,
    },
  };
}
