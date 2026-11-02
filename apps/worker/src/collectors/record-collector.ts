import { defineTool, type ToolDefinition } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';
import type { HttpEvidenceReceipt } from '../services/capture-http-request.js';
import { captureHttpRequest } from '../services/capture-http-request.js';
import {
  containsReplaySecret,
  type HttpReplayPlan,
  type HttpReplayVerification,
  hasLiteralReplayAuthentication,
} from '../services/http-replay.js';

function successResult(data: Record<string, unknown>) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify({ status: 'success', ...data }, null, 2) }],
    details: undefined,
  };
}

function errorResult(message: string) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify({ status: 'error', message, retryable: true }, null, 2) }],
    details: undefined,
  };
}

function toolResult(data: Record<string, unknown>) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }], details: undefined };
}

/** Accept a single explicit HTTP transfer; reject curl features that can add destinations. */
export function validateRecordTarget(args: readonly string[], targetUrl: string): void {
  const valueOptions = new Set([
    '--url',
    '--request',
    '--header',
    '--data',
    '--data-raw',
    '--data-binary',
    '--data-urlencode',
    '--json',
    '--form',
    '--form-string',
    '--cookie',
    '--cookie-jar',
    '--user',
    '--user-agent',
    '--referer',
    '--max-time',
    '--connect-timeout',
    '--output',
    '--dump-header',
    '--write-out',
  ]);
  const flagOptions = new Set([
    '--silent',
    '--show-error',
    '--insecure',
    '--include',
    '--head',
    '--compressed',
    '--fail',
    '--fail-with-body',
    '--globoff',
  ]);
  const shortValues = new Set(['-X', '-H', '-d', '-F', '-b', '-c', '-u', '-A', '-e', '-o', '-D', '-w']);
  const shortFlags = new Set(['-s', '-S', '-k', '-i', '-I', '-f', '-g']);
  const urls: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === undefined) throw new Error('Replay arguments are incomplete.');
    if (arg.startsWith('--')) {
      const index = arg.indexOf('=');
      const name = index < 0 ? arg : arg.slice(0, index);
      if (flagOptions.has(name) && index < 0) continue;
      if (!valueOptions.has(name)) throw new Error(`Unsupported curl option for record replay: ${name}`);
      const value = index < 0 ? args[++i] : arg.slice(index + 1);
      if (value === undefined || !value.length) throw new Error(`Missing value for ${name}`);
      if (name === '--url') urls.push(value);
    } else if (arg.startsWith('-')) {
      if (arg === '-') throw new Error(`Unsupported curl option for record replay: ${arg}`);
      for (let offset = 1; offset < arg.length; offset++) {
        const option = `-${arg[offset]}`;
        if (shortFlags.has(option)) continue;
        if (!shortValues.has(option)) throw new Error(`Unsupported curl option for record replay: ${arg}`);
        const value = offset + 1 < arg.length ? arg.slice(offset + 1) : args[++i];
        if (value === undefined || !value.length) throw new Error(`Missing value for ${option}`);
        break; // Everything after a value-taking flag is its value, not another option.
      }
    } else {
      urls.push(arg);
    }
  }
  const rawUrl = urls[0];
  if (urls.length !== 1 || rawUrl === undefined || ['{', '}', '[', ']'].some((character) => rawUrl.includes(character)))
    throw new Error('Replay must contain exactly one URL without curl URL globbing.');
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Replay URL is invalid.');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.origin !== new URL(targetUrl).origin)
    throw new Error('Replay URL must use the configured assessment target origin.');
}

export const MAX_RECORD_REPLAY_ATTEMPTS = 3;

export interface RecordReplayAttempt {
  attempt: number;
  stage: 'record' | 'record-expansion' | 'record-retry';
  record_log_path: string;
  error: string | null;
  capture_ids: string[];
  variable_diagnostics: Array<Record<string, unknown>>;
}

export interface RecordVerdict {
  finding_id: string;
  status: 'verified' | 'failed';
  reason: string;
  capture_ids: string[];
  frontend_status: 'available' | 'not_found' | 'unable_to_determine';
  frontend_url: string | null;
  frontend_trigger: string | null;
  frontend_reason: string;
  http_evidence_receipts?: HttpEvidenceReceipt[];
  http_replay_verification?: HttpReplayVerification;
  browser_verification?: {
    assertion_type: BrowserAssertionType;
    expected: string;
    observed: string;
    evidence_files: string[];
  };
  failure_kind?: string;
  error?: string;
  attempts?: number;
  replay_history?: RecordReplayAttempt[];
  partial_capture_ids?: string[];
  variable_diagnostics?: Array<Record<string, unknown>>;
  record_log_path?: string;
  stage?: 'record' | 'record-expansion' | 'record-retry';
}

export type BrowserAssertionType =
  | 'document_title_contains'
  | 'dialog_text_contains'
  | 'visible_text_contains'
  | 'url_contains';

export function createRecordCollector(options: {
  deliverablesDir: string;
  targetUrl: string;
  sourceDir: string;
  validIds: ReadonlySet<string>;
  secrets?: readonly string[];
  verificationPlans?: ReadonlyMap<string, HttpReplayPlan>;
  inspectReplayVariables?: (findingId: string) => Promise<string[]>;
  repairReplayVariables?: (
    findingId: string,
    plan: HttpReplayPlan,
    updates: Record<string, string>,
  ) => Promise<string[]>;
  xssFindingIds?: ReadonlySet<string>;
  validateBrowserEvidence?: (findingId: string, files: string[]) => Promise<string[]>;
  stage?: 'record' | 'record-expansion' | 'record-retry';
  recordLogPath?: string;
  verifyReplay?: (
    findingId: string,
    plan: HttpReplayPlan,
  ) => Promise<{
    verification?: HttpReplayVerification;
    error?: string;
    evidence?: HttpEvidenceReceipt[];
    variableDiagnostics?: Array<Record<string, unknown>>;
  }>;
}): { tools: ToolDefinition[]; getAll(): RecordVerdict[] } {
  const receipts = new Map<string, HttpEvidenceReceipt>();
  const verdicts = new Map<string, RecordVerdict>();
  const replayResults = new Map<string, { verification: HttpReplayVerification; receipts: HttpEvidenceReceipt[] }>();
  const failedReplays = new Set<string>();
  const variableRepairCounts = new Map<string, number>();
  const browserResults = new Map<string, NonNullable<RecordVerdict['browser_verification']>>();
  const replayAttempts = new Map<string, number>();
  const inFlight = new Set<string>();
  const replayHistory = new Map<string, RecordReplayAttempt[]>();
  const replayFailures = new Map<
    string,
    { error: string; captureIds: string[]; variableDiagnostics: Array<Record<string, unknown>> }
  >();
  const tools: ToolDefinition[] = [
    defineTool({
      name: 'verify_browser_assertion',
      label: 'Verify Browser Impact Assertion',
      description:
        "Record a deterministic observation from the Record agent Playwright session after reproducing the Exploit agent's documented browser steps. The host checks the assertion match and that every screenshot/evidence file exists under .shannon/scratchpad. XSS findings require a changed document title or a JavaScript dialog; a screenshot or visible reflected payload alone does not prove script execution.",
      parameters: Type.Object({
        finding_id: Type.String(),
        assertion_type: Type.Union([
          Type.Literal('document_title_contains'),
          Type.Literal('dialog_text_contains'),
          Type.Literal('visible_text_contains'),
          Type.Literal('url_contains'),
        ]),
        expected: Type.String({ minLength: 1, maxLength: 500 }),
        observed: Type.String({ minLength: 1, maxLength: 2000 }),
        evidence_files: Type.Array(Type.String({ minLength: 1 }), { minItems: 1, maxItems: 5 }),
      }),
      async execute(_id, input) {
        if (!options.validIds.has(input.finding_id))
          return errorResult('Finding is not present in the exploitation queues.');
        if (verdicts.has(input.finding_id)) return errorResult('This finding already has a record verdict.');
        browserResults.delete(input.finding_id);
        if (input.expected.trim() !== input.expected || !input.observed.includes(input.expected))
          return errorResult('The observed browser value does not contain the expected impact marker.');
        if (
          options.xssFindingIds?.has(input.finding_id) &&
          !['document_title_contains', 'dialog_text_contains'].includes(input.assertion_type)
        )
          return errorResult(
            'XSS browser verification requires a JavaScript execution signal: document title or dialog text.',
          );
        if (!options.validateBrowserEvidence) return errorResult('Host browser evidence validation is unavailable.');
        try {
          const validatedFiles = await options.validateBrowserEvidence(input.finding_id, input.evidence_files);
          const result = {
            assertion_type: input.assertion_type,
            expected: input.expected,
            observed: input.observed,
            evidence_files: validatedFiles,
          };
          browserResults.set(input.finding_id, result);
          return successResult({ finding_id: input.finding_id, status: 'assertion_passed', ...result });
        } catch (error) {
          return errorResult(error instanceof Error ? error.message : 'Browser evidence could not be validated.');
        }
      },
    }),
    defineTool({
      name: 'verify_http_replay',
      label: 'Execute Exploit Verification Plan',
      description:
        'Execute the structured HTTP verification plan saved by the Exploit agent. The host evaluates each status/body impact assertion and captures every real request/response. A passing result is required for a verified HTTP verdict.',
      parameters: Type.Object({ finding_id: Type.String() }),
      async execute(_id, input) {
        if (!options.validIds.has(input.finding_id))
          return errorResult('Finding is not present in the exploitation queues.');
        if (verdicts.has(input.finding_id) || replayResults.has(input.finding_id))
          return errorResult('This finding already has a verdict or a passing replay; submit its verification result.');
        if (inFlight.has(input.finding_id)) return errorResult('A replay for this finding is already running.');
        if ((replayAttempts.get(input.finding_id) ?? 0) >= MAX_RECORD_REPLAY_ATTEMPTS)
          return errorResult(
            'The three-attempt replay limit has been reached. Record a failed verdict for exploit review.',
          );
        if (!options.verifyReplay) return errorResult('Host replay verifier is unavailable.');
        const plan = options.verificationPlans?.get(input.finding_id);
        if (!plan)
          return errorResult(
            'No structured HTTP verification plan was saved for this finding; record a failed verdict for review.',
          );
        if ([...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])].some((step) => step.follow_redirects))
          return errorResult('HTTP replay redirects are not supported by Record; record a failed verdict for review.');
        if (hasLiteralReplayAuthentication(plan) || containsReplaySecret(plan, options.secrets ?? []))
          return errorResult(
            'Replay plan contains literal authentication material; record a failed verdict for review.',
          );
        replayResults.delete(input.finding_id);
        replayAttempts.set(input.finding_id, (replayAttempts.get(input.finding_id) ?? 0) + 1);
        inFlight.add(input.finding_id);
        try {
          const result = await options.verifyReplay(input.finding_id, plan);
          const capturedReceipts = result.evidence ?? [];
          for (const receipt of capturedReceipts) receipts.set(receipt.capture_id, receipt);
          if (!result.verification) {
            failedReplays.add(input.finding_id);
            replayFailures.set(input.finding_id, {
              error: result.error ?? 'Replay assertions did not pass.',
              captureIds: capturedReceipts.map((receipt) => receipt.capture_id),
              variableDiagnostics: result.variableDiagnostics ?? [],
            });
            return toolResult({
              status: 'error',
              message: result.error ?? 'Replay assertions did not pass.',
              captures: capturedReceipts,
            });
          }
          if (!capturedReceipts.length || capturedReceipts.some((receipt) => !receipt.complete)) {
            failedReplays.add(input.finding_id);
            replayFailures.set(input.finding_id, {
              error: 'Replay assertions passed, but complete request/response packet captures are missing.',
              captureIds: capturedReceipts.map((receipt) => receipt.capture_id),
              variableDiagnostics: result.variableDiagnostics ?? [],
            });
            return toolResult({
              status: 'error',
              message: 'Replay assertions passed, but complete request/response packet captures are missing.',
              captures: capturedReceipts,
            });
          }
          replayResults.set(input.finding_id, { verification: result.verification, receipts: capturedReceipts });
          failedReplays.delete(input.finding_id);
          replayFailures.delete(input.finding_id);
          return successResult({
            finding_id: input.finding_id,
            verification: result.verification,
            captures: capturedReceipts,
          });
        } catch (error) {
          failedReplays.add(input.finding_id);
          replayFailures.set(input.finding_id, {
            error: error instanceof Error ? error.message : 'Replay verification failed.',
            captureIds: [],
            variableDiagnostics: [],
          });
          return errorResult(error instanceof Error ? error.message : 'Replay verification failed.');
        } finally {
          inFlight.delete(input.finding_id);
          const failure = replayFailures.get(input.finding_id);
          const history = replayHistory.get(input.finding_id) ?? [];
          history.push({
            attempt: replayAttempts.get(input.finding_id) ?? 0,
            stage: options.stage ?? 'record',
            record_log_path: options.recordLogPath ?? 'agents/record.log',
            error: failure?.error ?? null,
            capture_ids:
              failure?.captureIds ?? replayResults.get(input.finding_id)?.receipts.map((item) => item.capture_id) ?? [],
            variable_diagnostics: failure?.variableDiagnostics ?? [],
          });
          replayHistory.set(input.finding_id, history);
        }
      },
    }),
    defineTool({
      name: 'inspect_replay_variables',
      label: 'Inspect Saved Replay Variable Names',
      description:
        'After a failed replay, inspect which private variable names have saved values without revealing the values. Use Exploit evidence and logs to determine whether a correction is supported.',
      parameters: Type.Object({ finding_id: Type.String() }),
      async execute(_id, input) {
        if (!options.validIds.has(input.finding_id))
          return errorResult('Finding is not present in the exploitation queues.');
        if (!failedReplays.has(input.finding_id) || replayResults.has(input.finding_id))
          return errorResult('A replay must fail before its saved variables can be inspected.');
        if (!options.inspectReplayVariables) return errorResult('Private replay variable inspection is unavailable.');
        try {
          return successResult({
            finding_id: input.finding_id,
            saved_variable_names: await options.inspectReplayVariables(input.finding_id),
          });
        } catch (error) {
          return errorResult(error instanceof Error ? error.message : 'Replay variables could not be inspected.');
        }
      },
    }),
    defineTool({
      name: 'update_replay_variables',
      label: 'Correct Replay Variables',
      description:
        'After a failed replay, update private input values for variables referenced by the saved plan. Inspect the Exploit stage evidence and logs first; use only observed values, never guesses. Response-extracted values and configured credentials cannot be overwritten. A corrected value is written privately and must be verified by rerunning the unchanged plan. At most two corrections are allowed per finding.',
      parameters: Type.Object({
        finding_id: Type.String(),
        variables: Type.Record(Type.String(), Type.String(), { minProperties: 1 }),
      }),
      async execute(_id, input) {
        if (!options.validIds.has(input.finding_id))
          return errorResult('Finding is not present in the exploitation queues.');
        if (!failedReplays.has(input.finding_id) || replayResults.has(input.finding_id))
          return errorResult('A replay must fail before its variables can be corrected.');
        if (!options.repairReplayVariables) return errorResult('Private replay variable repair is unavailable.');
        if ((replayAttempts.get(input.finding_id) ?? 0) >= MAX_RECORD_REPLAY_ATTEMPTS)
          return errorResult('The replay attempt limit has been reached; submit a failed verdict for review.');
        const attempts = variableRepairCounts.get(input.finding_id) ?? 0;
        if (attempts >= 2) return errorResult('The replay variable correction limit has been reached.');
        const plan = options.verificationPlans?.get(input.finding_id);
        if (!plan) return errorResult('No structured replay plan exists for this finding.');
        try {
          const changed = await options.repairReplayVariables(input.finding_id, plan, input.variables);
          variableRepairCounts.set(input.finding_id, attempts + 1);
          failedReplays.delete(input.finding_id);
          return successResult({ finding_id: input.finding_id, updated_variable_names: changed, retry_required: true });
        } catch (error) {
          return errorResult(error instanceof Error ? error.message : 'Replay variables could not be updated.');
        }
      },
    }),
    defineTool({
      name: 'capture_http_request',
      label: 'Replay and Capture HTTP Request',
      description:
        'Run one HTTP request taken from the exploit evidence and save its real request/response packet. Pass curl arguments without the curl command.',
      parameters: Type.Object({
        finding_id: Type.String(),
        curl_arguments: Type.Array(Type.String(), { minItems: 1 }),
        timeout_seconds: Type.Optional(Type.Number({ minimum: 1, maximum: 600 })),
      }),
      async execute(_id, input, signal) {
        if (!options.validIds.has(input.finding_id))
          return errorResult('Finding is not present in the exploitation queues.');
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
      description:
        'Record a successful verification as verified, or a failed/inconclusive verification as failed. Every verified result must cite all complete packets from a passing HTTP replay; XSS additionally requires a passing JavaScript execution assertion.',
      parameters: Type.Object({
        finding_id: Type.String(),
        status: Type.Union([Type.Literal('verified'), Type.Literal('failed')]),
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
        failure_kind: Type.Optional(Type.String({ minLength: 1 })),
        error: Type.Optional(Type.String({ minLength: 1 })),
        variable_diagnostics: Type.Optional(Type.Array(Type.Record(Type.String(), Type.Unknown()))),
        record_log_path: Type.Optional(Type.String({ minLength: 1 })),
      }),
      async execute(_id, input) {
        if (!options.validIds.has(input.finding_id))
          return errorResult('Finding is not present in the exploitation queues.');
        if (verdicts.has(input.finding_id)) return errorResult('This finding already has a record verdict.');
        if (inFlight.has(input.finding_id))
          return errorResult('Wait for the running replay before submitting a verdict.');
        const usedReceipts = input.capture_ids.map((id) => receipts.get(id));
        if (usedReceipts.some((item) => !item || item.finding_id !== input.finding_id))
          return errorResult('Every capture ID must be a real capture from this agent for this finding.');
        const replay = replayResults.get(input.finding_id);
        const browser = browserResults.get(input.finding_id);
        const httpVerified =
          !!replay &&
          replay.verification.assertion_count >= 1 &&
          input.capture_ids.length === replay.receipts.length &&
          replay.receipts.every((receipt) => input.capture_ids.includes(receipt.capture_id));
        if (input.status === 'verified' && !httpVerified)
          return errorResult(
            'A verified finding requires every complete capture from a passing HTTP replay. Diagnostic captures and browser-only observations are insufficient.',
          );
        if (input.status === 'verified' && options.xssFindingIds?.has(input.finding_id) && !browser)
          return errorResult(
            'XSS cannot be marked verified without a passing browser assertion that confirms JavaScript execution.',
          );
        if (input.status === 'verified' && input.capture_ids.length && !httpVerified)
          return errorResult(
            'A verified verdict cannot cite partial or unrelated HTTP captures; cite all captures from the passing replay.',
          );
        if (
          (input.frontend_status === 'available' && (!input.frontend_url || !input.frontend_trigger)) ||
          (input.frontend_status !== 'available' && (input.frontend_url !== null || input.frontend_trigger !== null))
        )
          return errorResult('Frontend URL and trigger details must match the frontend status.');
        const failure = replayFailures.get(input.finding_id);
        const verdict: RecordVerdict = {
          ...input,
          attempts: replayAttempts.get(input.finding_id) ?? 0,
          replay_history: replayHistory.get(input.finding_id) ?? [],
          http_evidence_receipts: usedReceipts.filter((item): item is HttpEvidenceReceipt => !!item),
          ...(input.status === 'verified' && replay ? { http_replay_verification: replay.verification } : {}),
          ...(browser ? { browser_verification: browser } : {}),
          ...(input.status === 'failed'
            ? {
                failure_kind:
                  (replayAttempts.get(input.finding_id) ?? 0) >= MAX_RECORD_REPLAY_ATTEMPTS
                    ? 'retry_exhausted'
                    : (input.failure_kind ?? (failure ? 'replay_failed' : 'verification_incomplete')),
                error: input.error ?? failure?.error ?? input.reason,
                partial_capture_ids: failure?.captureIds ?? input.capture_ids,
                variable_diagnostics: input.variable_diagnostics ?? failure?.variableDiagnostics ?? [],
                record_log_path: options.recordLogPath ?? input.record_log_path ?? 'agents/record.log',
                stage: options.stage ?? 'record',
              }
            : { stage: options.stage ?? 'record' }),
        };
        verdicts.set(input.finding_id, verdict);
        return successResult({ recorded: input.finding_id, status: input.status });
      },
    }),
  ];
  return {
    tools,
    getAll: () => [
      ...verdicts.values(),
      ...[...replayAttempts]
        .filter(([id]) => !verdicts.has(id))
        .map(
          ([id, attempts]): RecordVerdict => ({
            finding_id: id,
            status: 'failed',
            reason:
              attempts >= MAX_RECORD_REPLAY_ATTEMPTS && !replayResults.has(id)
                ? 'The replay attempt limit was exhausted.'
                : 'The Record agent did not submit a verdict.',
            capture_ids: [],
            frontend_status: 'unable_to_determine',
            frontend_url: null,
            frontend_trigger: null,
            frontend_reason: 'No frontend verdict was submitted before replay exhaustion.',
            failure_kind:
              attempts >= MAX_RECORD_REPLAY_ATTEMPTS && !replayResults.has(id) ? 'retry_exhausted' : 'missing_verdict',
            error: replayFailures.get(id)?.error ?? 'Replay verification failed.',
            attempts,
            replay_history: replayHistory.get(id) ?? [],
            partial_capture_ids: replayFailures.get(id)?.captureIds ?? [],
            variable_diagnostics: replayFailures.get(id)?.variableDiagnostics ?? [],
            record_log_path: options.recordLogPath ?? 'agents/record.log',
            stage: options.stage ?? 'record',
          }),
        ),
    ],
  };
}
