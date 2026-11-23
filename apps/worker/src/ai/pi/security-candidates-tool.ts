// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent-facing `find_security_candidates` tool.
 *
 * The tool is read-only with respect to the target sources: it writes the *complete* candidate list
 * for the requested page into the Shannon scratchpad and returns only a short header, a bounded
 * preview, and the artifact path. The full list therefore survives large pages that would otherwise
 * be cut by an inline size cap. It never prints absolute paths or full rule detail, and it never
 * claims a candidate is a confirmed vulnerability.
 */

import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { findSecurityCandidates } from '../../services/java-security/service.js';
import {
  type FindSecurityCandidatesOutput,
  type SecurityCandidate,
  VULNERABILITY_TYPES,
} from '../../services/java-security/types.js';

/** Hard cap for the inline fallback text used when the artifact cannot be written. */
const MAX_INLINE_CHARS = 16_000;
/** Number of candidates echoed inline when the artifact was written; the rest live in the file. */
const INLINE_PREVIEW_CANDIDATES = 8;
/** Relative scratchpad subdirectory that holds the full result artifacts. */
export const SECURITY_CANDIDATES_RESULTS_SUBDIR = '.shannon/scratchpad/security-candidates';

export interface SecurityCandidatesToolOptions {
  /** Absolute directory for the full result artifacts. Defaults to `<sourceDir>/<RESULTS_SUBDIR>`. */
  readonly outputDir?: string;
}

export function isSecurityCandidatesAgent(agentName: string | null): boolean {
  return agentName === 'pre-recon' || agentName === 'recon';
}

function headerLines(output: FindSecurityCandidatesOutput): string[] {
  const lines: string[] = [
    `status=${output.status} type=${output.vulnerability_type} requested=${output.requested} returned=${output.returned} ` +
      `matched_before_filter=${output.stats.matched_before_filter} filtered_constant=${output.stats.filtered_constant} ` +
      `duplicates=${output.stats.excluded_duplicates} files_scanned=${output.stats.files_scanned} ` +
      `files_skipped=${output.stats.files_skipped} parse_errors=${output.stats.parse_errors} timeout=${output.stats.timeout}`,
  ];
  if (output.snapshot_id !== undefined) lines.push(`snapshot=${output.snapshot_id.slice(0, 16)}`);
  return lines;
}

function candidateLines(candidate: SecurityCandidate): string[] {
  const location = `${candidate.file}:${candidate.line}${candidate.column !== undefined ? `:${candidate.column}` : ''}`;
  const symbol = candidate.containing_symbol !== undefined ? ` ${candidate.containing_symbol}` : '';
  return [
    `- ${location} [${candidate.role}/${candidate.category}] ${candidate.function} ` +
      `(${candidate.confidence}, const=${candidate.constant_state})${symbol}`,
    `    ${candidate.code}`,
    `    ${candidate.reason}`,
  ];
}

function tailLines(output: FindSecurityCandidatesOutput, warnings: readonly string[]): string[] {
  const lines: string[] = [];
  if (output.next_cursor !== undefined) lines.push(`next_cursor=${output.next_cursor}`);
  if (warnings.length > 0) lines.push(`warnings: ${warnings.join('; ')}`);
  return lines;
}

function clampInline(text: string): string {
  return text.length > MAX_INLINE_CHARS ? `${text.slice(0, MAX_INLINE_CHARS - 20)}\n…(truncated)` : text;
}

function slug(value: string): string {
  const cleaned = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '');
  return cleaned.slice(0, 40) || 'query';
}

/** Deterministic artifact name for one query page; the cursor hash keeps pages distinct. */
function artifactName(vulnerabilityType: string, functionName: string | undefined, cursor: string | undefined): string {
  const parts = [vulnerabilityType];
  if (functionName !== undefined) parts.push(slug(functionName));
  if (cursor !== undefined) {
    parts.push(`page-${createHash('sha256').update(cursor).digest('hex').slice(0, 8)}`);
  }
  return `${parts.join('_')}.txt`;
}

function toPosix(value: string): string {
  return value.split(path.sep).join('/');
}

/** Build the agent-facing text: full list when the artifact failed, else header + preview + path. */
function formatInline(
  output: FindSecurityCandidatesOutput,
  warnings: readonly string[],
  artifactPath: string | undefined,
): string {
  const header = headerLines(output);
  if (artifactPath !== undefined) {
    const preview = output.candidates.slice(0, INLINE_PREVIEW_CANDIDATES).flatMap(candidateLines);
    const remaining = output.candidates.length - Math.min(output.candidates.length, INLINE_PREVIEW_CANDIDATES);
    const lines = [
      ...header,
      `results_file=${artifactPath}`,
      `results_count=${output.returned} of ${output.stats.matched_before_filter} matched candidates written to results_file`,
      ...(output.returned === 0 ? ['(no candidates)'] : preview),
      ...(remaining > 0 ? [`…(+${remaining} more candidate${remaining === 1 ? '' : 's'} in results_file)`] : []),
      ...tailLines(output, warnings),
      `hint: read or grep results_file for the full untruncated list; the inline preview above is partial.`,
    ];
    return clampInline(lines.join('\n'));
  }
  const lines = [
    ...header,
    ...(output.returned === 0 ? ['(no candidates)'] : output.candidates.flatMap(candidateLines)),
    ...tailLines(output, warnings),
  ];
  return clampInline(lines.join('\n'));
}

/** Create the candidate search tool bound to one source root. */
export function createSecurityCandidatesTool(
  sourceDir: string,
  options: SecurityCandidatesToolOptions = {},
): ToolDefinition {
  const outputDir = options.outputDir ?? path.join(sourceDir, SECURITY_CANDIDATES_RESULTS_SUBDIR);
  return defineTool({
    name: 'find_security_candidates',
    label: 'Find Security Candidates',
    description:
      'Read-only navigation aid for Java source. Returns possible source/sink/security-boundary ' +
      'locations (xx.java:line) for a vulnerability type, optionally narrowed by a function or API ' +
      'name. The complete candidate list for the requested page is written to a Shannon scratchpad ' +
      'file and its path is returned; the inline response is only a short preview. Results are ' +
      'unverified leads; absence of results is not proof of absence.',
    promptSnippet:
      'find_security_candidates: write the full Java source/sink/boundary candidate list to a scratchpad file and return its path',
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

      const warnings = [...output.warnings];
      let resultsFile: string | undefined;
      try {
        const absolutePath = path.join(
          outputDir,
          artifactName(params.vulnerability_type, params.function_name, params.cursor),
        );
        const body = [
          ...headerLines(output),
          ...(output.returned === 0 ? ['(no candidates)'] : output.candidates.flatMap(candidateLines)),
          ...tailLines(output, warnings),
        ].join('\n');
        await mkdir(outputDir, { recursive: true });
        await writeFile(absolutePath, `${body}\n`, 'utf8');
        resultsFile = toPosix(path.relative(sourceDir, absolutePath));
      } catch (error) {
        warnings.push(
          `failed to write full result artifact: ${error instanceof Error ? error.message : String(error)}; ` +
            'returning the candidate list inline instead',
        );
      }

      const text = formatInline(output, warnings, resultsFile);
      return {
        content: [{ type: 'text' as const, text }],
        details: resultsFile !== undefined ? { results_file: resultsFile, returned: output.returned } : undefined,
      };
    },
  });
}
