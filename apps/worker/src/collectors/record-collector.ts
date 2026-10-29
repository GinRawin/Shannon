import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import { captureHttpRequest } from '../services/capture-http-request.js';
import type { HttpEvidenceReceipt } from '../services/capture-http-request.js';

function successResult(data: Record<string, unknown>) {
  return { content: [{ type: 'text' as const, text: JSON.stringify({ status: 'success', ...data }, null, 2) }], details: undefined };
}

function errorResult(message: string) {
  return { content: [{ type: 'text' as const, text: JSON.stringify({ status: 'error', message, retryable: true }, null, 2) }], details: undefined };
}

/** Accept a single explicit HTTP transfer; reject curl features that can add destinations. */
export function validateRecordTarget(args: readonly string[], targetUrl: string): void {
  const valueOptions = new Set(['--url', '--request', '--header', '--data', '--data-raw', '--data-binary', '--data-urlencode', '--json', '--form', '--form-string', '--cookie', '--cookie-jar', '--user', '--user-agent', '--referer', '--max-time', '--connect-timeout', '--output', '--dump-header', '--write-out']);
  const flagOptions = new Set(['--silent', '--show-error', '--insecure', '--include', '--head', '--compressed', '--fail', '--fail-with-body', '--globoff']);
  const shortValues = new Set(['-X', '-H', '-d', '-F', '-b', '-c', '-u', '-A', '-e', '-o', '-D', '-w']);
  const shortFlags = new Set(['-s', '-S', '-k', '-i', '-I', '-f', '-g']);
  const urls: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg.startsWith('--')) {
      const index = arg.indexOf('=');
      const name = index < 0 ? arg : arg.slice(0, index);
      if (flagOptions.has(name) && index < 0) continue;
      if (!valueOptions.has(name)) throw new Error(`Unsupported curl option for record replay: ${name}`);
      const value = index < 0 ? args[++i] : arg.slice(index + 1);
      if (value === undefined || !value.length) throw new Error(`Missing value for ${name}`);
      if (name === '--url') urls.push(value);
    } else if (arg.startsWith('-')) {
      if (shortFlags.has(arg)) continue;
      const option = arg.slice(0, 2);
      if (!shortValues.has(option)) throw new Error(`Unsupported curl option for record replay: ${arg}`);
      const value = arg.length > 2 ? arg.slice(2) : args[++i];
      if (value === undefined || !value.length) throw new Error(`Missing value for ${option}`);
    } else {
      urls.push(arg);
    }
  }
  if (urls.length !== 1 || /[{}\[\]]/.test(urls[0]!)) throw new Error('Replay must contain exactly one URL without curl URL globbing.');
  let url: URL;
  try { url = new URL(urls[0]!); } catch { throw new Error('Replay URL is invalid.'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.origin !== new URL(targetUrl).origin)
    throw new Error('Replay URL must use the configured assessment target origin.');
}

export interface RecordVerdict {
  finding_id: string;
  status: 'verified' | 'manual_review';
  reason: string;
  capture_ids: string[];
  frontend_status: 'available' | 'not_found' | 'unable_to_determine';
  frontend_url: string | null;
  frontend_trigger: string | null;
  frontend_reason: string;
  http_evidence_receipts?: HttpEvidenceReceipt[];
}

export function createRecordCollector(options: {
  deliverablesDir: string;
  targetUrl: string;
  sourceDir: string;
  validIds: ReadonlySet<string>;
  secrets?: readonly string[];
}): { tools: ToolDefinition[]; getAll(): RecordVerdict[] } {
  const receipts = new Map<string, HttpEvidenceReceipt>();
  const verdicts = new Map<string, RecordVerdict>();
  const tools: ToolDefinition[] = [
    defineTool({
      name: 'capture_http_request',
      label: 'Replay and Capture HTTP Request',
      description: 'Run one HTTP request taken from the exploit evidence and save its real request/response packet. Pass curl arguments without the curl command.',
      parameters: Type.Object({
        finding_id: Type.String(),
        curl_arguments: Type.Array(Type.String(), { minItems: 1 }),
        timeout_seconds: Type.Optional(Type.Number({ minimum: 1, maximum: 600 })),
      }),
      async execute(_id, input, signal) {
        if (!options.validIds.has(input.finding_id)) return errorResult('Finding is not present in the exploitation queues.');
        try {
          validateRecordTarget(input.curl_arguments, options.targetUrl);
        } catch (error) {
          return errorResult(error instanceof Error ? error.message : 'Replay URL is invalid.');
        }
        try {
          const result = await captureHttpRequest({
            deliverablesDir: options.deliverablesDir,
            findingId: input.finding_id,
            curlArguments: input.curl_arguments,
            cwd: options.sourceDir,
            secrets: options.secrets,
            signal,
            ...(input.timeout_seconds !== undefined ? { timeoutSeconds: input.timeout_seconds } : {}),
          });
          receipts.set(result.receipt.capture_id, result.receipt);
          return successResult({ ...result.receipt, stdout: result.stdout, stderr: result.stderr });
        } catch (error) {
          return errorResult(error instanceof Error ? error.message : 'HTTP replay failed.');
        }
      },
    }),
    defineTool({
      name: 'record_verification',
      label: 'Record Verification Result',
      description: 'Record a successful replay as verified, or a failed/inconclusive replay as manual_review. A verified result must cite captured request/response IDs from this record agent.',
      parameters: Type.Object({
        finding_id: Type.String(),
        status: Type.Union([Type.Literal('verified'), Type.Literal('manual_review')]),
        reason: Type.String({ minLength: 1 }),
        capture_ids: Type.Array(Type.String()),
        frontend_status: Type.Union([
          Type.Literal('available'),
          Type.Literal('not_found'),
          Type.Literal('unable_to_determine'),
        ]),
        frontend_url: Type.Union([Type.String({ minLength: 1 }), Type.Null()]),
        frontend_trigger: Type.Union([Type.String({ minLength: 1 }), Type.Null()]),
        frontend_reason: Type.String({ minLength: 1 }),
      }),
      async execute(_id, input) {
        if (!options.validIds.has(input.finding_id)) return errorResult('Finding is not present in the exploitation queues.');
        if (verdicts.has(input.finding_id)) return errorResult('This finding already has a record verdict.');
        const usedReceipts = input.capture_ids.map((id) => receipts.get(id));
        if (usedReceipts.some((item) => !item || item.finding_id !== input.finding_id))
          return errorResult('Every capture ID must be a real capture from this agent for this finding.');
        if (input.status === 'verified' && (usedReceipts.length === 0 || usedReceipts.some((item) => !item?.complete)))
          return errorResult('A verified finding requires at least one complete captured replay exchange.');
        if (
          (input.frontend_status === 'available' && (!input.frontend_url || !input.frontend_trigger)) ||
          (input.frontend_status !== 'available' && (input.frontend_url !== null || input.frontend_trigger !== null))
        ) return errorResult('Frontend URL and trigger details must match the frontend status.');
        const verdict: RecordVerdict = {
          ...input,
          http_evidence_receipts: usedReceipts.filter((item): item is HttpEvidenceReceipt => !!item),
        };
        verdicts.set(input.finding_id, verdict);
        return successResult({ recorded: input.finding_id, status: input.status });
      },
    }),
  ];
  return { tools, getAll: () => [...verdicts.values()] };
}
