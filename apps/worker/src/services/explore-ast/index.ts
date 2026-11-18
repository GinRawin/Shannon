// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Inverted structural-feature index and weighted-Dice recall.
 *
 * One index is built per language so a Java seed can never be scored against a JavaScript
 * candidate. Weights are the base weight of a feature kind scaled by inverse document frequency,
 * and the recall score is a weighted Dice overlap. The index deliberately keeps the threshold low;
 * the ordered tree match decides what is really a clone.
 */

import { baseWeightFor, extractFeatures, featureKind } from './features.js';
import type { AstFeatureWeights, AstForest } from './types.js';

export interface IndexedForest {
  readonly id: number;
  readonly forest: AstForest;
  readonly excerpt: string;
  /** Precomputed weighted feature norm; kept here to avoid recomputing on every query. */
  readonly norm: number;
}

export interface RetrievalCandidate {
  readonly forestId: number;
  readonly score: number;
  readonly shared: number;
}

export interface StructuralIndex {
  readonly forests: readonly IndexedForest[];
  readonly weightOf: (feature: string) => number;
  retrieve(
    seedFeatures: ReadonlyMap<string, number>,
    seedNorm: number,
    topN: number,
    minScore: number,
  ): RetrievalCandidate[];
}

function idfFor(documentFrequency: number, documentCount: number): number {
  return Math.log((1 + documentCount) / (1 + documentFrequency)) + 1;
}

class StructuralIndexImpl implements StructuralIndex {
  readonly forests: IndexedForest[];
  private readonly postings = new Map<string, number[]>();
  private readonly weightCache = new Map<string, number>();

  constructor(
    forests: IndexedForest[],
    private readonly baseWeights: AstFeatureWeights,
  ) {
    this.forests = forests;
  }

  add(feature: string, forestId: number, count: number): void {
    const list = this.postings.get(feature);
    if (list === undefined) this.postings.set(feature, [forestId, count]);
    else list.push(forestId, count);
  }

  weightOf(feature: string): number {
    const cached = this.weightCache.get(feature);
    if (cached !== undefined) return cached;
    const list = this.postings.get(feature);
    const documentFrequency = list === undefined ? 0 : list.length / 2;
    const weight =
      baseWeightFor(featureKind(feature), this.baseWeights) *
      idfFor(documentFrequency, Math.max(1, this.forests.length));
    this.weightCache.set(feature, weight);
    return weight;
  }

  retrieve(
    seedFeatures: ReadonlyMap<string, number>,
    seedNorm: number,
    topN: number,
    minScore: number,
  ): RetrievalCandidate[] {
    const shared = new Map<number, number>();
    // Sorted iteration keeps floating-point accumulation deterministic across runs.
    for (const feature of [...seedFeatures.keys()].sort()) {
      const list = this.postings.get(feature);
      if (list === undefined) continue;
      const seedCount = seedFeatures.get(feature) ?? 0;
      const weight = this.weightOf(feature);
      for (let index = 0; index < list.length; index += 2) {
        const forestId = list[index];
        const candidateCount = list[index + 1];
        if (forestId === undefined || candidateCount === undefined) continue;
        const contribution = weight * Math.min(seedCount, candidateCount);
        shared.set(forestId, (shared.get(forestId) ?? 0) + contribution);
      }
    }
    const ranked: RetrievalCandidate[] = [];
    for (const [forestId, overlap] of shared) {
      const candidateNorm = this.forests[forestId]?.norm ?? 0;
      const denominator = seedNorm + candidateNorm;
      const score = denominator === 0 ? 0 : (2 * overlap) / denominator;
      if (score >= minScore) ranked.push({ forestId, score, shared: overlap });
    }
    ranked.sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      return left.forestId - right.forestId;
    });
    return ranked.slice(0, topN);
  }
}

export interface IndexInput {
  readonly forest: AstForest;
  readonly excerpt: string;
}

/**
 * Build a language-scoped index. Document frequency is counted first so weights are stable, and a
 * forest is never indexed twice in the same language pass.
 */
export function buildStructuralIndex(inputs: readonly IndexInput[], baseWeights: AstFeatureWeights): StructuralIndex {
  const featureMaps = inputs.map((input) => extractFeatures(input.forest));
  const documentFrequency = new Map<string, number>();
  for (const features of featureMaps) {
    for (const feature of features.keys()) documentFrequency.set(feature, (documentFrequency.get(feature) ?? 0) + 1);
  }
  const weightOf = (feature: string): number =>
    baseWeightFor(featureKind(feature), baseWeights) *
    idfFor(documentFrequency.get(feature) ?? 0, Math.max(1, inputs.length));

  const forests: IndexedForest[] = [];
  for (let id = 0; id < inputs.length; id++) {
    const input = inputs[id];
    const features = featureMaps[id];
    if (input === undefined || features === undefined) continue;
    let norm = 0;
    for (const [feature, count] of features) norm += weightOf(feature) * count;
    forests.push({ id, forest: input.forest, excerpt: input.excerpt, norm });
  }

  const index = new StructuralIndexImpl(forests, baseWeights);
  for (let id = 0; id < featureMaps.length; id++) {
    const features = featureMaps[id];
    if (features === undefined) continue;
    for (const [feature, count] of features) index.add(feature, id, count);
  }
  return index;
}

/** Weighted norm of a query feature multiset, using the index's live IDF weights. */
export function weightedNorm(index: StructuralIndex, features: ReadonlyMap<string, number>): number {
  let norm = 0;
  for (const [feature, count] of features) norm += index.weightOf(feature) * count;
  return norm;
}
