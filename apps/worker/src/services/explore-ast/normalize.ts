// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Tree-sitter parse tree -> language-independent normalized AST.
 *
 * Punctuation and keyword tokens are dropped (the grammar node type already encodes them) and the
 * remaining named nodes are mapped to a small category set. Children keep their original order and
 * their grammar field, so `if (x) f()` and `if (x) { f(); }` remain structurally distinct and a
 * call inside an `if` body can never be confused with a call outside it. Identifiers and literals
 * are collapsed to leaves; the only retained text is a bounded structural `detail` (operators, call
 * arity) and a soft API label that never participates in a hard structural comparison.
 */

import type { Node as TsNode } from 'web-tree-sitter';
import { AstParserUnavailableError, parseSource } from './parser.js';
import type { AstLanguage, AstNodeCategory, NormalizedAstNode } from './types.js';

/** Nodes that are dropped and whose children are spliced into the parent, keeping their field. */
const TRANSPARENT_NODES = new Set(['expression_statement', 'parenthesized_expression', 'empty_statement']);

/** Named nodes that carry no structure (comments, shebangs) and are always discarded. */
const IGNORED_NODES = new Set([
  'comment',
  'line_comment',
  'block_comment',
  'hash_bang_line',
  'html_comment',
  'documentation_comment',
]);

const JS_CATEGORIES: ReadonlyMap<string, AstNodeCategory> = new Map<string, AstNodeCategory>([
  ['program', 'BLOCK'],
  ['statement_block', 'BLOCK'],
  ['class_body', 'BLOCK'],
  ['switch_body', 'BLOCK'],
  ['lexical_declaration', 'DECLARATION'],
  ['variable_declaration', 'DECLARATION'],
  ['function_declaration', 'DECLARATION'],
  ['generator_function_declaration', 'DECLARATION'],
  ['function_signature', 'DECLARATION'],
  ['class_declaration', 'DECLARATION'],
  ['abstract_class_declaration', 'DECLARATION'],
  ['method_definition', 'DECLARATION'],
  ['abstract_method_signature', 'DECLARATION'],
  ['method_signature', 'DECLARATION'],
  ['public_field_definition', 'DECLARATION'],
  ['property_signature', 'DECLARATION'],
  ['import_statement', 'DECLARATION'],
  ['import_clause', 'DECLARATION'],
  ['export_statement', 'DECLARATION'],
  ['export_clause', 'DECLARATION'],
  ['namespace_import', 'DECLARATION'],
  ['named_imports', 'DECLARATION'],
  ['import_specifier', 'DECLARATION'],
  ['export_specifier', 'DECLARATION'],
  ['required_parameter', 'DECLARATION'],
  ['optional_parameter', 'DECLARATION'],
  ['formal_parameters', 'DECLARATION'],
  ['object_pattern', 'DECLARATION'],
  ['array_pattern', 'DECLARATION'],
  ['assignment_expression', 'ASSIGNMENT'],
  ['augmented_assignment_expression', 'ASSIGNMENT'],
  ['variable_declarator', 'ASSIGNMENT'],
  ['pair', 'ASSIGNMENT'],
  ['call_expression', 'CALL'],
  ['new_expression', 'CALL'],
  ['decorator', 'CALL'],
  ['await_expression', 'AWAIT'],
  ['return_statement', 'RETURN'],
  ['yield_expression', 'RETURN'],
  ['if_statement', 'IF'],
  ['conditional_expression', 'IF'],
  ['switch_statement', 'IF'],
  ['switch_case', 'IF'],
  ['switch_default', 'IF'],
  ['for_statement', 'LOOP'],
  ['for_in_statement', 'LOOP'],
  ['while_statement', 'LOOP'],
  ['do_statement', 'LOOP'],
  ['try_statement', 'TRY'],
  ['catch_clause', 'TRY'],
  ['finally_clause', 'TRY'],
  ['binary_expression', 'BINARY_OP'],
  ['unary_expression', 'UNARY_OP'],
  ['update_expression', 'UNARY_OP'],
  ['member_expression', 'MEMBER_ACCESS'],
  ['subscript_expression', 'INDEX_ACCESS'],
  ['arrow_function', 'LAMBDA'],
  ['function_expression', 'LAMBDA'],
  ['generator_function', 'LAMBDA'],
  ['function', 'LAMBDA'],
  ['identifier', 'IDENTIFIER'],
  ['property_identifier', 'IDENTIFIER'],
  ['shorthand_property_identifier', 'IDENTIFIER'],
  ['shorthand_property_identifier_pattern', 'IDENTIFIER'],
  ['private_property_identifier', 'IDENTIFIER'],
  ['type_identifier', 'IDENTIFIER'],
  ['nested_identifier', 'IDENTIFIER'],
  ['statement_identifier', 'IDENTIFIER'],
  ['string', 'LITERAL'],
  ['number', 'LITERAL'],
  ['true', 'LITERAL'],
  ['false', 'LITERAL'],
  ['null', 'LITERAL'],
  ['undefined', 'LITERAL'],
  ['template_string', 'LITERAL'],
  ['regex', 'LITERAL'],
  ['regex_pattern', 'LITERAL'],
  ['string_fragment', 'LITERAL'],
  ['escape_sequence', 'LITERAL'],
  ['jsx_text', 'LITERAL'],
]);

const JAVA_CATEGORIES: ReadonlyMap<string, AstNodeCategory> = new Map<string, AstNodeCategory>([
  ['program', 'BLOCK'],
  ['block', 'BLOCK'],
  ['class_body', 'BLOCK'],
  ['constructor_body', 'BLOCK'],
  ['static_initializer', 'BLOCK'],
  ['interface_body', 'BLOCK'],
  ['enum_body', 'BLOCK'],
  ['record_body', 'BLOCK'],
  ['annotation_type_body', 'BLOCK'],
  ['switch_block', 'BLOCK'],
  ['local_variable_declaration', 'DECLARATION'],
  ['field_declaration', 'DECLARATION'],
  ['method_declaration', 'DECLARATION'],
  ['constructor_declaration', 'DECLARATION'],
  ['class_declaration', 'DECLARATION'],
  ['interface_declaration', 'DECLARATION'],
  ['enum_declaration', 'DECLARATION'],
  ['record_declaration', 'DECLARATION'],
  ['annotation_type_declaration', 'DECLARATION'],
  ['import_declaration', 'DECLARATION'],
  ['package_declaration', 'DECLARATION'],
  ['formal_parameters', 'DECLARATION'],
  ['formal_parameter', 'DECLARATION'],
  ['spread_parameter', 'DECLARATION'],
  ['modifiers', 'DECLARATION'],
  ['annotation', 'DECLARATION'],
  ['module_declaration', 'DECLARATION'],
  ['enum_constant', 'DECLARATION'],
  ['assignment_expression', 'ASSIGNMENT'],
  ['variable_declarator', 'ASSIGNMENT'],
  ['method_invocation', 'CALL'],
  ['object_creation_expression', 'CALL'],
  ['explicit_constructor_invocation', 'CALL'],
  ['return_statement', 'RETURN'],
  ['if_statement', 'IF'],
  ['ternary_expression', 'IF'],
  ['switch_expression', 'IF'],
  ['switch_statement', 'IF'],
  ['switch_rule', 'IF'],
  ['switch_label', 'IF'],
  ['switch_block_statement_group', 'IF'],
  ['for_statement', 'LOOP'],
  ['enhanced_for_statement', 'LOOP'],
  ['while_statement', 'LOOP'],
  ['do_statement', 'LOOP'],
  ['try_statement', 'TRY'],
  ['catch_clause', 'TRY'],
  ['finally_clause', 'TRY'],
  ['try_with_resources_statement', 'TRY'],
  ['binary_expression', 'BINARY_OP'],
  ['unary_expression', 'UNARY_OP'],
  ['update_expression', 'UNARY_OP'],
  ['field_access', 'MEMBER_ACCESS'],
  ['array_access', 'INDEX_ACCESS'],
  ['lambda_expression', 'LAMBDA'],
  ['identifier', 'IDENTIFIER'],
  ['type_identifier', 'IDENTIFIER'],
  ['scoped_identifier', 'IDENTIFIER'],
  ['scoped_type_identifier', 'IDENTIFIER'],
  ['string_literal', 'LITERAL'],
  ['character_literal', 'LITERAL'],
  ['decimal_integer_literal', 'LITERAL'],
  ['hex_integer_literal', 'LITERAL'],
  ['octal_integer_literal', 'LITERAL'],
  ['binary_integer_literal', 'LITERAL'],
  ['decimal_floating_point_literal', 'LITERAL'],
  ['hex_floating_point_literal', 'LITERAL'],
  ['true', 'LITERAL'],
  ['false', 'LITERAL'],
  ['null_literal', 'LITERAL'],
  ['multiline_string_fragment', 'LITERAL'],
  ['string_fragment', 'LITERAL'],
]);

function isJavaFamily(language: AstLanguage): boolean {
  return language === 'java';
}

function categorize(language: AstLanguage, nodeType: string): AstNodeCategory {
  const table = isJavaFamily(language) ? JAVA_CATEGORIES : JS_CATEGORIES;
  return table.get(nodeType) ?? 'OTHER';
}

/** First unnamed child token of an operator node, i.e. the operator text itself. */
function operatorText(node: TsNode): string | undefined {
  for (let index = 0; index < node.childCount; index++) {
    const child = node.child(index);
    if (child !== null && !child.isNamed) return child.type;
  }
  return undefined;
}

function argumentCount(node: TsNode): number {
  const args = node.childForFieldName('arguments') ?? node.childForFieldName('argument_list');
  return args === null ? 0 : args.namedChildCount;
}

/** Bounded structural detail. Identifiers and literal values are never stored here. */
function detailFor(node: TsNode, category: AstNodeCategory): string | undefined {
  switch (category) {
    case 'BINARY_OP':
    case 'UNARY_OP':
      return operatorText(node);
    case 'CALL':
      return `a${argumentCount(node)}`;
    default:
      return undefined;
  }
}

/** Soft callee label, used only as a low-weight feature and never as a hard condition. */
function softLabelFor(node: TsNode): string | undefined {
  const callee = node.childForFieldName('function') ?? node.childForFieldName('name') ?? node.childForFieldName('type');
  if (callee === null) return undefined;
  if (callee.type === 'member_expression' || callee.type === 'field_access') {
    const property = callee.childForFieldName('property') ?? callee.childForFieldName('field');
    return property?.text?.slice(0, 64);
  }
  if (callee.type === 'identifier' || callee.type === 'type_identifier') return callee.text.slice(0, 64);
  return undefined;
}

interface BuildContext {
  readonly language: AstLanguage;
  readonly nodes: NormalizedAstNode[];
}

function buildNode(
  node: TsNode,
  field: string | undefined,
  parentId: number,
  context: BuildContext,
): NormalizedAstNode {
  const category = categorize(context.language, node.type);
  const id = context.nodes.length;
  const normalized: NormalizedAstNode = {
    id,
    type: category,
    field,
    detail: detailFor(node, category),
    softLabel: category === 'CALL' ? softLabelFor(node) : undefined,
    parentId,
    children: [],
    startByte: node.startIndex,
    endByte: node.endIndex,
    startLine: node.startPosition.row + 1,
    endLine: node.endPosition.row + 1,
  };
  context.nodes.push(normalized);
  if (category !== 'IDENTIFIER' && category !== 'LITERAL') {
    normalized.children.push(...buildChildren(node, normalized, context, field));
  }
  return normalized;
}

/** Normalized children of a node, splicing transparent nodes and dropping noise/unnamed tokens. */
function buildChildren(
  node: TsNode,
  parent: NormalizedAstNode,
  context: BuildContext,
  inheritedField: string | undefined,
): NormalizedAstNode[] {
  const result: NormalizedAstNode[] = [];
  for (let index = 0; index < node.childCount; index++) {
    const child = node.child(index);
    if (child === null || !child.isNamed || IGNORED_NODES.has(child.type)) continue;
    const field = node.fieldNameForChild(index) ?? inheritedField ?? undefined;
    if (TRANSPARENT_NODES.has(child.type)) {
      result.push(...buildChildren(child, parent, context, field));
      continue;
    }
    result.push(buildNode(child, field, parent.id, context));
  }
  return result;
}

export interface NormalizedTree {
  readonly language: AstLanguage;
  readonly root: NormalizedAstNode;
  readonly nodes: readonly NormalizedAstNode[];
}

function finalizeRoot(context: BuildContext, fileRootId: number): NormalizedAstNode {
  const fileRoot = context.nodes[fileRootId];
  if (fileRoot === undefined) throw new AstParserUnavailableError('Normalized AST lost its root node.');
  const synthetic: NormalizedAstNode = {
    id: -1,
    type: 'FOREST',
    field: undefined,
    detail: undefined,
    softLabel: undefined,
    parentId: -1,
    children: fileRoot.children,
    startByte: fileRoot.startByte,
    endByte: fileRoot.endByte,
    startLine: fileRoot.startLine,
    endLine: fileRoot.endLine,
  };
  for (const child of synthetic.children) child.parentId = synthetic.id;
  return synthetic;
}

/** Normalize a parsed source. Returns a synthetic FOREST root whose children are top-level nodes. */
export function normalizeParsedSource(parsed: { language: AstLanguage; root: TsNode }): NormalizedTree {
  const context: BuildContext = { language: parsed.language, nodes: [] };
  const fileRoot = buildNode(parsed.root, undefined, -1, context);
  const root = finalizeRoot(context, fileRoot.id);
  return { language: parsed.language, root, nodes: context.nodes };
}

/** Parse and normalize one source string in a single step. */
export async function parseAndNormalize(
  language: AstLanguage,
  text: string,
): Promise<NormalizedTree & { hasError: boolean }> {
  const parsed = await parseSource(language, text);
  const normalized = normalizeParsedSource(parsed);
  return { ...normalized, hasError: parsed.hasError };
}
