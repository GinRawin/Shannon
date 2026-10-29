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

export function createExploreCollector(args: {
  sinks: ReadonlyMap<string, { vulnerabilityClass: string; locations: ReadonlyMap<string, ReadonlySet<number>> }>;
}): { tools: ToolDefinition[]; getAll(): ExploreTemplate[] } {
  const templates = new Map<string, ExploreTemplate>();
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
      const key = `${input.finding_id}:${input.sink_file}:${input.sink_line}:${input.regex}`;
      if (templates.has(key)) return result({ status: 'error', message: 'This template was already submitted.' });
      templates.set(key, { ...input });
      return result({ status: 'success', accepted: true });
    },
  });
  return { tools: [tool], getAll: () => [...templates.values()] };
}
