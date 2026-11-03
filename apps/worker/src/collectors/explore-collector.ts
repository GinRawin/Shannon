import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { stringEnum } from './schema.js';

function result(value: Record<string, unknown>) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }], details: undefined };
}

export interface ExploreTemplate {
  finding_id: string;
  vulnerability_class: string;
  sink_file: string;
  sink_line: number;
  regex: string;
  rationale: string;
}

export interface ExploreSkip {
  finding_id: string;
  reason: string;
}

export function createExploreCollector(args: {
  sinks: ReadonlyMap<string, { vulnerabilityClass: string; locations: ReadonlyMap<string, ReadonlySet<number>> }>;
  verifiedFindingIds: ReadonlySet<string>;
}): { tools: ToolDefinition[]; getAll(): ExploreTemplate[]; getSkips(): ExploreSkip[] } {
  const templates = new Map<string, ExploreTemplate>();
  const skips = new Map<string, ExploreSkip>();
  const tool = defineTool({
    name: 'submit_explore_template',
    label: 'Submit Sink Search Template',
    description: 'Submit one conservative Rust-regex template grounded in a confirmed finding sink. The host verifies it matches the supplied sink line and then searches source code deterministically.',
    parameters: Type.Object({
      finding_id: Type.String({ minLength: 1 }),
      vulnerability_class: stringEnum(['injection', 'xss', 'auth', 'authz', 'ssrf', 'miscellaneous']),
      sink_file: Type.String({ minLength: 1 }),
      sink_line: Type.Integer({ minimum: 1 }),
      regex: Type.String({ minLength: 1, maxLength: 300 }),
      rationale: Type.String({ minLength: 1, maxLength: 500 }),
    }),
    async execute(_id, input) {
      const trustedSink = args.sinks.get(input.finding_id);
      if (!trustedSink || trustedSink.vulnerabilityClass !== input.vulnerability_class)
        return result({ status: 'error', message: 'Finding is not a record-verified sink of this class.' });
      const sinkLines = trustedSink.locations.get(input.sink_file);
      if (!sinkLines || !sinkLines.has(input.sink_line))
        return result({ status: 'error', message: 'Sink file is not one of the recorded code locations for this finding.' });
      if (templates.size >= 200)
        return result({ status: 'error', message: 'Template limit reached for this scan.' });
      if (skips.has(input.finding_id))
        return result({
          status: 'error',
          message: 'This finding was already skipped. Do not both skip a finding and submit a template for it.',
        });
      const key = `${input.finding_id}:${input.sink_file}:${input.sink_line}:${input.regex}`;
      if (templates.has(key)) return result({ status: 'error', message: 'This template was already submitted.' });
      templates.set(key, { ...input });
      return result({ status: 'success', accepted: true });
    },
  });
  const skipTool = defineTool({
    name: 'skip_explore_finding',
    label: 'Skip Explore Finding',
    description:
      'Record why a record-verified finding has no usable source template. Every trusted sink must either receive a template or an explicit skip; silent omission is treated as a coverage gap.',
    parameters: Type.Object({
      finding_id: Type.String({ minLength: 1 }),
      reason: Type.String({ minLength: 1, maxLength: 500 }),
    }),
    async execute(_id, input) {
      if (!args.verifiedFindingIds.has(input.finding_id))
        return result({ status: 'error', message: 'Finding is not record-verified; it cannot be skipped here.' });
      if ([...templates.values()].some((template) => template.finding_id === input.finding_id))
        return result({
          status: 'error',
          message: 'This finding already has a submitted template. Do not skip it as well.',
        });
      skips.set(input.finding_id, { finding_id: input.finding_id, reason: input.reason });
      return result({ status: 'success', recorded: true });
    },
  });
  return { tools: [tool, skipTool], getAll: () => [...templates.values()], getSkips: () => [...skips.values()] };
}
