// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent-facing `find_security_candidates` tool.
 *
 * The tool is read-only and returns bounded text: a location, its role, confidence, and constant
 * state, plus a cursor for the next page. It never prints absolute paths or full rule detail, and it
 * never claims a candidate is a confirmed vulnerability.
 */

import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { findSecurityCandidates } from '../../services/java-security/service.js';
import { type FindSecurityCandidatesOutput, VULNERABILITY_TYPES } from '../../services/java-security/types.js';

const MAX_TOOL_OUTPUT_CHARS = 16_000;

export function isSecurityCandidatesAgent(agentName: string | null): boolean {
  return agentName === 'pre-recon' || agentName === 'recon';
}

function formatOutput(output: FindSecurityCandidatesOutput): string {
  const lines: string[] = [];
  lines.push(
    `status=${output.status} type=${output.vulnerability_type} requested=${output.requested} returned=${output.returned} ` +
      `matched_before_filter=${output.stats.matched_before_filter} filtered_constant=${output.stats.filtered_constant} ` +
      `duplicates=${output.stats.excluded_duplicates} files_scanned=${output.stats.files_scanned} ` +
      `files_skipped=${output.stats.files_skipped} parse_errors=${output.stats.parse_errors} timeout=${output.stats.timeout}`,
  );
  if (output.snapshot_id !== undefined) lines.push(`snapshot=${output.snapshot_id.slice(0, 16)}`);
  if (output.candidates.length === 0) lines.push('(no candidates)');
  for (const candidate of output.candidates) {
    const location = `${candidate.file}:${candidate.line}${candidate.column !== undefined ? `:${candidate.column}` : ''}`;
    const symbol = candidate.containing_symbol !== undefined ? ` ${candidate.containing_symbol}` : '';
    lines.push(
      `- ${location} [${candidate.role}/${candidate.category}] ${candidate.function} ` +
        `(${candidate.confidence}, const=${candidate.constant_state})${symbol}`,
    );
    lines.push(`    ${candidate.code}`);
    lines.push(`    ${candidate.reason}`);
  }
  if (output.next_cursor !== undefined) lines.push(`next_cursor=${output.next_cursor}`);
  if (output.warnings.length > 0) lines.push(`warnings: ${output.warnings.join('; ')}`);

  const text = lines.join('\n');
  return text.length > MAX_TOOL_OUTPUT_CHARS ? `${text.slice(0, MAX_TOOL_OUTPUT_CHARS - 20)}\n…(truncated)` : text;
}

/** Create the read-only candidate search tool bound to one source root. */
export function createSecurityCandidatesTool(sourceDir: string): ToolDefinition {
  return defineTool({
    name: 'find_security_candidates',
    label: 'Find Security Candidates',
    description:
      'Read-only navigation aid for Java source. Returns possible source/sink/security-boundary ' +
      'locations (xx.java:line) for a vulnerability type, optionally narrowed by a function or API ' +
      'name. Results are unverified leads; absence of results is not proof of absence.',
    promptSnippet: 'find_security_candidates: locate Java source/sink/boundary candidates by vulnerability type',
    parameters: Type.Object({
      vulnerability_type: Type.Union(
        VULNERABILITY_TYPES.map((value) => Type.Literal(value)),
        { description: 'Vulnerability class to search for.' },
      ),
      limit: Type.Integer({
        minimum: 1,
        maximum: 100,
        description: 'Maximum number of candidates to return this page (1..100).',
      }),
      function_name: Type.Optional(
        Type.String({
          description:
            'Optional method or fully-qualified API name to narrow the search, e.g. "executeQuery" or "java.sql.Statement.executeQuery".',
        }),
      ),
      cursor: Type.Optional(
        Type.String({ description: 'Opaque cursor from a previous call to fetch the next page of the same query.' }),
      ),
    }),
    async execute(_toolCallId, params) {
      const output = await findSecurityCandidates(
        {
          vulnerability_type: params.vulnerability_type,
          limit: params.limit,
          ...(params.function_name !== undefined && { function_name: params.function_name }),
          ...(params.cursor !== undefined && { cursor: params.cursor }),
        },
        { sourceDir },
      );
      return { content: [{ type: 'text' as const, text: formatOutput(output) }], details: undefined };
    },
  });
}
