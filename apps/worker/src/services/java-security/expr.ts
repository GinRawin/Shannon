// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Bounded conversion of a Tree-sitter Java expression into a serializable fragment.
 *
 * The raw index stores this fragment instead of a resolved constant so that filtering policy can
 * change without re-parsing source. Anything we do not model is preserved as `other`, which the
 * constant evaluator treats as unknown (retain, never drop).
 */

import type { ExprNode } from './types.js';

const MAX_EXPR_DEPTH = 16;

function unescapeStringLiteral(text: string): string {
  const inner = text.length >= 2 && text.startsWith('"') && text.endsWith('"') ? text.slice(1, -1) : text;
  return inner.replace(/\\(.)/g, (_match, ch: string) => {
    switch (ch) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case 'b':
        return '\b';
      case 'f':
        return '\f';
      case '"':
        return '"';
      case "'":
        return "'";
      case '\\':
        return '\\';
      default:
        return ch;
    }
  });
}

const NUMBER_LITERALS = new Set([
  'decimal_integer_literal',
  'hex_integer_literal',
  'octal_integer_literal',
  'binary_integer_literal',
  'decimal_floating_point_literal',
  'hex_floating_point_literal',
]);

const LITERAL_NODE_TYPES = new Set([
  'string_literal',
  'character_literal',
  'true',
  'false',
  'null_literal',
  ...NUMBER_LITERALS,
]);

export function isLiteralNodeType(type: string): boolean {
  return LITERAL_NODE_TYPES.has(type);
}

type TsNode = import('web-tree-sitter').Node;

function firstNamed(node: TsNode): TsNode | null {
  return node.namedChildren[0] ?? null;
}

/** Convert a Tree-sitter node into a bounded `ExprNode`; unknown shapes become `other`. */
export function toExpr(node: TsNode, depth = 0): ExprNode {
  if (depth > MAX_EXPR_DEPTH) return { k: 'other', text: node.text };
  switch (node.type) {
    case 'string_literal':
      return { k: 'literal', type: 'string', value: unescapeStringLiteral(node.text) };
    case 'character_literal':
      return { k: 'literal', type: 'char', value: node.text };
    case 'true':
    case 'false':
      return { k: 'literal', type: 'bool', value: node.text };
    case 'null_literal':
      return { k: 'literal', type: 'null', value: 'null' };
    default:
      break;
  }
  if (NUMBER_LITERALS.has(node.type)) return { k: 'literal', type: 'number', value: node.text };

  switch (node.type) {
    case 'identifier':
      return { k: 'ident', name: node.text };
    case 'field_access': {
      const target = node.childForFieldName('object');
      const name = node.childForFieldName('field');
      return {
        k: 'member',
        target: target ? toExpr(target, depth + 1) : null,
        name: name?.text ?? node.text,
        text: node.text,
      };
    }
    case 'method_invocation': {
      const object = node.childForFieldName('object');
      const name = node.childForFieldName('name');
      const args = node.childForFieldName('arguments');
      return {
        k: 'call',
        receiver: object?.text ?? null,
        name: name?.text ?? '',
        args: args ? args.namedChildren.map((child) => toExpr(child, depth + 1)) : [],
      };
    }
    case 'object_creation_expression': {
      const type = node.childForFieldName('type');
      const args = node.childForFieldName('arguments');
      return {
        k: 'new',
        typeName: type?.text ?? '',
        args: args ? args.namedChildren.map((child) => toExpr(child, depth + 1)) : [],
      };
    }
    case 'array_creation_expression': {
      const initializer = node.namedChildren.find((child) => child.type === 'array_initializer');
      return {
        k: 'array',
        elements: initializer ? initializer.namedChildren.map((child) => toExpr(child, depth + 1)) : [],
      };
    }
    case 'array_initializer':
      return { k: 'array', elements: node.namedChildren.map((child) => toExpr(child, depth + 1)) };
    case 'binary_expression': {
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      const operator = node.childForFieldName('operator');
      if (left && right) {
        return {
          k: 'binary',
          op: operator?.text ?? '',
          left: toExpr(left, depth + 1),
          right: toExpr(right, depth + 1),
        };
      }
      return { k: 'other', text: node.text };
    }
    case 'parenthesized_expression': {
      const inner = firstNamed(node);
      return inner ? { k: 'paren', inner: toExpr(inner, depth + 1) } : { k: 'other', text: node.text };
    }
    case 'cast_expression': {
      const value = node.childForFieldName('value');
      return value ? toExpr(value, depth + 1) : { k: 'other', text: node.text };
    }
    default:
      return { k: 'other', text: node.text };
  }
}
