// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Bounded, fail-open constant evaluation for the sensitive position of a rule.
 *
 * This is deliberately *not* a taint solver. It only folds literals and simple single-assignment
 * locals within one method. Anything else — parameters, fields, calls, branches, aliases — is
 * reported as `dynamic` or `unknown`, and the candidate is retained. If a rule's sensitive target
 * is not recognized, no filtering is ever applied.
 */

import type { ConstEval, ConstState, ExprNode, FileIndexEntry, NormalizedRule, RawSite } from './types.js';

export interface EvalContext {
  readonly file: FileIndexEntry;
  readonly symbol: string | undefined;
  readonly useLine: number;
  readonly visited: ReadonlySet<string>;
  readonly depth: number;
}

const MAX_EVAL_DEPTH = 24;

function stringify(value: string | number | boolean | null): string {
  if (value === null) return 'null';
  return String(value);
}

function evalIdent(name: string, ctx: EvalContext): ConstEval {
  if (ctx.symbol === undefined) return { state: 'dynamic' };
  const bucket = ctx.file.locals[ctx.symbol];
  const def = bucket?.[name];
  if (def === undefined) return { state: 'dynamic' };
  if (def.isParameter === true) return { state: 'dynamic' };
  if (def.reassigned || def.inBranch)
    return { state: 'unknown', reason: 'value is conditionally or repeatedly assigned' };
  if (def.line > ctx.useLine) return { state: 'unknown', reason: 'use precedes the visible assignment' };
  if (def.expr === undefined) return { state: 'unknown', reason: 'declaration has no analyzable initializer' };
  const key = `${ctx.symbol}:${name}@${def.line}`;
  if (ctx.visited.has(key)) return { state: 'unknown', reason: 'cyclic local reference' };
  if (ctx.depth > MAX_EVAL_DEPTH) return { state: 'unknown', reason: 'constant evaluation depth exceeded' };
  return evalExpr(def.expr, {
    ...ctx,
    useLine: def.line,
    visited: new Set([...ctx.visited, key]),
    depth: ctx.depth + 1,
  });
}

/** Evaluate one expression fragment to constant/dynamic/unknown. */
export function evalExpr(expr: ExprNode, ctx: EvalContext): ConstEval {
  switch (expr.k) {
    case 'literal': {
      switch (expr.type) {
        case 'number': {
          const parsed = Number(expr.value);
          return { state: 'constant', value: Number.isFinite(parsed) ? parsed : expr.value };
        }
        case 'bool':
          return { state: 'constant', value: expr.value === 'true' };
        case 'null':
          return { state: 'constant', value: null };
        default:
          return { state: 'constant', value: expr.value };
      }
    }
    case 'ident':
      return evalIdent(expr.name, ctx);
    case 'member':
    case 'new':
      return { state: 'dynamic' };
    case 'call':
      return { state: 'dynamic' };
    case 'paren':
      return evalExpr(expr.inner, ctx);
    case 'array': {
      let sawUnknown = false;
      for (const element of expr.elements) {
        const evaluated = evalExpr(element, ctx);
        if (evaluated.state === 'dynamic') return { state: 'dynamic' };
        if (evaluated.state === 'unknown') sawUnknown = true;
      }
      return sawUnknown ? { state: 'unknown', reason: 'array contains an unevaluable element' } : { state: 'constant' };
    }
    case 'binary': {
      if (expr.op !== '+') {
        const left = evalExpr(expr.left, ctx);
        const right = evalExpr(expr.right, ctx);
        if (left.state === 'dynamic' || right.state === 'dynamic') return { state: 'dynamic' };
        return { state: 'unknown', reason: 'non-concatenation operator' };
      }
      const left = evalExpr(expr.left, ctx);
      const right = evalExpr(expr.right, ctx);
      if (left.state === 'unknown' || right.state === 'unknown') {
        return { state: 'unknown', reason: 'concatenation operand is unknown' };
      }
      if (left.state === 'dynamic' || right.state === 'dynamic') return { state: 'dynamic' };
      const lv = left.value ?? null;
      const rv = right.value ?? null;
      if (typeof lv === 'string' || typeof rv === 'string') {
        return { state: 'constant', value: stringify(lv) + stringify(rv) };
      }
      if (typeof lv === 'number' && typeof rv === 'number') return { state: 'constant', value: lv + rv };
      return { state: 'unknown', reason: 'unsupported concatenation of non-string values' };
    }
    default:
      return { state: 'unknown', reason: 'unsupported expression form' };
  }
}

function contextFor(site: RawSite, file: FileIndexEntry, useLine: number): EvalContext {
  return { file, symbol: site.symbol, useLine, visited: new Set(), depth: 0 };
}

export interface SensitiveEvaluation {
  readonly state: ConstState;
  readonly details: readonly ConstEval[];
}

/** Evaluate the rule's sensitive argument positions for one site. */
export function evaluateSensitive(rule: NormalizedRule, site: RawSite, file: FileIndexEntry): SensitiveEvaluation {
  const { target, indexes } = rule.sensitive;
  if (target === 'return' || target === 'parameter' || target === 'none' || target === 'xml_body') {
    return { state: 'not_applicable', details: [] };
  }
  if (target === 'receiver') {
    return { state: 'unknown', details: [] };
  }
  const argIndexes = indexes && indexes.length > 0 ? [...indexes] : site.args.map((_arg, index) => index);
  if (argIndexes.length === 0) return { state: 'unknown', details: [] };
  const details: ConstEval[] = [];
  for (const index of argIndexes) {
    const arg = site.args[index];
    if (arg === undefined) {
      details.push({ state: 'unknown', reason: `argument ${index} is not present` });
      continue;
    }
    details.push(evalExpr(arg.expr, contextFor(site, file, arg.line)));
  }
  if (details.some((d) => d.state === 'unknown')) return { state: 'unknown', details };
  if (details.some((d) => d.state === 'dynamic')) return { state: 'dynamic', details };
  return { state: 'constant', details };
}

// --- format-aware transform ---------------------------------------------------------------

interface FormatScan {
  readonly referenced: readonly number[];
  readonly valid: boolean;
}

/** Parse a Java format string just far enough to know which argument indexes it consumes. */
function scanFormat(format: string): FormatScan {
  const referenced: number[] = [];
  let sequential = 0;
  let i = 0;
  while (i < format.length) {
    if (format[i] !== '%') {
      i += 1;
      continue;
    }
    i += 1;
    if (format[i] === '%') {
      i += 1;
      continue;
    }
    if (format[i] === 'n') {
      i += 1;
      continue;
    }
    const indexStart = i;
    while (i < format.length && format[i] !== undefined && /[0-9]/.test(format[i] as string)) i += 1;
    let explicit: number | undefined;
    if (i < format.length && format[i] === '$') {
      explicit = Number(format.slice(indexStart, i));
      i += 1;
    } else {
      i = indexStart;
    }
    while (i < format.length && format[i] !== undefined && /[-#+ 0,(<]/.test(format[i] as string)) i += 1;
    while (i < format.length && format[i] !== undefined && /[0-9]/.test(format[i] as string)) i += 1;
    if (i < format.length && format[i] === '.') {
      i += 1;
      while (i < format.length && format[i] !== undefined && /[0-9]/.test(format[i] as string)) i += 1;
    }
    const conversion = format[i];
    if (conversion === undefined || !/[bBhHsScCdoxXeEfgGaAtT%n]/.test(conversion)) {
      return { referenced, valid: false };
    }
    if (conversion !== '%' && conversion !== 'n') {
      if (explicit !== undefined) {
        if (!Number.isInteger(explicit) || explicit < 1) return { referenced, valid: false };
        referenced.push(explicit - 1);
      } else {
        referenced.push(sequential);
        sequential += 1;
      }
    }
    i += 1;
  }
  return { referenced, valid: true };
}

export interface FormatEvaluation {
  readonly state: ConstState;
}

/** Decide whether a `String.format`/`Formatter.format` transform has a provably constant result. */
export function evaluateFormatTransform(site: RawSite, file: FileIndexEntry): FormatEvaluation {
  const formatArg = site.args[0];
  if (formatArg === undefined) return { state: 'unknown' };
  const formatValue = evalExpr(formatArg.expr, contextFor(site, file, formatArg.line));
  if (formatValue.state !== 'constant' || typeof formatValue.value !== 'string') {
    return { state: formatValue.state === 'dynamic' ? 'dynamic' : 'unknown' };
  }
  const scan = scanFormat(formatValue.value);
  if (!scan.valid) return { state: 'unknown' };
  let sawDynamic = false;
  for (const index of scan.referenced) {
    const arg = site.args[index + 1];
    if (arg === undefined) return { state: 'unknown' };
    const evaluated = evalExpr(arg.expr, contextFor(site, file, arg.line));
    if (evaluated.state === 'dynamic') sawDynamic = true;
    else if (evaluated.state !== 'constant') return { state: 'unknown' };
  }
  return { state: sawDynamic ? 'dynamic' : 'constant' };
}

export function constStateFromEval(evaluated: ConstEval): ConstState {
  if (evaluated.state === 'constant') return 'constant';
  if (evaluated.state === 'dynamic') return 'dynamic';
  return 'unknown';
}
