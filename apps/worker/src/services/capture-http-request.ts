// Execute the validation request and capture that same invocation, never a later replay.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { type CurlInvocation, snapshotCurlInvocation } from './curl-invocation.js';
import { type ParsedHttpTrace, parseCurlTrace } from './http-capture.js';

export interface HttpEvidenceReceipt {
  capture_id: string;
  finding_id: string;
  file: string;
  sha256: string;
  captured_at: string;
  exit_code: number;
  complete: boolean;
}

export interface CapturedHttpRecord extends ParsedHttpTrace {
  schema_version: 2 | 3;
  capture_id: string;
  finding_id: string;
  captured_at: string;
  exit_code: number;
  trace: string;
  invocation?: CurlInvocation;
  provenance?: { kind: 'historical_import'; original_file: string; sha256: string; command_log?: string };
}

export function validateCurlCaptureArguments(args: readonly string[]): void {
  if (!args.length || args[0] === 'curl') throw new Error('Pass curl arguments only, without an extra curl command.');
  // Configuration files could override tracing or start additional transfers.
  // The tool catalog takes argv, not a shell command; shell metacharacters stay literal.
  const valueOptions = new Set([
    '--data',
    '--data-binary',
    '--data-raw',
    '--data-urlencode',
    '--json',
    '--form',
    '--form-string',
    '--header',
    '--cookie',
    '--cookie-jar',
    '--user-agent',
    '--referer',
    '--user',
    '--proxy',
    '--request',
    '--output',
    '--dump-header',
    '--write-out',
    '--url',
    '--upload-file',
    '--max-time',
    '--connect-timeout',
    '--cacert',
    '--cert',
    '--key',
    '--resolve',
    '--connect-to',
  ]);
  const shortValues = new Set('AbcCdDeEFHmoPrtTuUwXxyzY'.split(''));
  for (let index = 0; index < args.length; index++) {
    const arg = args[index] as string;
    if (arg === '--') throw new Error('Use --url instead of an inner -- separator, which disables capture options.');
    if (arg.startsWith('--')) {
      const option = arg.split('=')[0] as string;
      if (
        /^--(?:next|parallel|trace|config)/.test(option) ||
        ['--config', '--next', '--parallel', '--trace'].some((name) => name.startsWith(option))
      )
        throw new Error('Separate transfers, curl config files, and custom trace options are not supported.');
      if (!arg.includes('=') && valueOptions.has(option)) index++;
    } else if (arg.startsWith('-')) {
      for (const [offset, flag] of [...arg.slice(1)].entries()) {
        if (['K', ':', 'Z'].includes(flag))
          throw new Error('Curl config files and parallel/separate transfers are not supported.');
        if (shortValues.has(flag)) {
          if (offset === arg.length - 2) index++;
          break; // The remainder of this token, or the next token, is data.
        }
      }
    }
  }
}

export function completeHttpRecord(record: Pick<CapturedHttpRecord, 'trace' | 'exit_code'>): boolean {
  const parsed = parseCurlTrace(record.trace);
  return (
    record.exit_code === 0 &&
    parsed.errors.length === 0 &&
    parsed.exchanges.length > 0 &&
    parsed.exchanges.every((exchange) => Boolean(exchange.request_base64 && exchange.response_base64))
  );
}

export async function persistCapturedTrace(args: {
  deliverablesDir: string;
  findingId: string;
  trace: string;
  exitCode: number;
  capturedAt?: string;
  invocation?: CurlInvocation;
  provenance?: CapturedHttpRecord['provenance'];
}): Promise<HttpEvidenceReceipt> {
  if (!/^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(args.findingId))
    throw new Error('Invalid HTTP evidence finding ID');
  const captureId = randomUUID();
  const relative = `http-exchanges/${args.findingId}/exchange-${Date.now()}-${captureId}.json`;
  const target = path.join(args.deliverablesDir, relative);
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  const record: CapturedHttpRecord = {
    schema_version: args.invocation ? 3 : 2,
    capture_id: captureId,
    finding_id: args.findingId,
    captured_at: args.capturedAt ?? new Date().toISOString(),
    exit_code: args.exitCode,
    ...parseCurlTrace(args.trace),
    trace: args.trace,
    ...(args.invocation ? { invocation: args.invocation } : {}),
    ...(args.provenance ? { provenance: args.provenance } : {}),
  };
  const contents = `${JSON.stringify(record, null, 2)}\n`;
  await writeFile(target, contents, { mode: 0o600, flag: 'wx', flush: true });
  return {
    capture_id: captureId,
    finding_id: args.findingId,
    file: relative,
    sha256: createHash('sha256').update(contents).digest('hex'),
    captured_at: record.captured_at,
    exit_code: args.exitCode,
    complete: completeHttpRecord(record),
  };
}

/** Verify persisted bytes against the host's execution receipt, then decode the trace again. */
export async function readVerifiedHttpEvidence(dir: string, receipt: HttpEvidenceReceipt): Promise<CapturedHttpRecord> {
  if (
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(receipt.capture_id) ||
    !/^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(receipt.finding_id) ||
    !new RegExp(`^http-exchanges/${receipt.finding_id}/exchange-[a-zA-Z0-9-]+\\.json$`).test(receipt.file)
  )
    throw new Error('Invalid HTTP evidence receipt');
  const contents = await readFile(path.join(dir, receipt.file), 'utf8');
  if (createHash('sha256').update(contents).digest('hex') !== receipt.sha256)
    throw new Error('HTTP evidence was modified after capture');
  const record = JSON.parse(contents) as CapturedHttpRecord;
  if (
    record.capture_id !== receipt.capture_id ||
    record.finding_id !== receipt.finding_id ||
    record.captured_at !== receipt.captured_at ||
    record.exit_code !== receipt.exit_code ||
    typeof record.trace !== 'string' ||
    completeHttpRecord(record) !== receipt.complete
  )
    throw new Error('HTTP evidence does not match its execution receipt');
  return { ...record, ...parseCurlTrace(record.trace) };
}

export async function captureHttpRequest(args: {
  deliverablesDir: string;
  findingId: string;
  curlArguments: readonly string[];
  timeoutSeconds?: number;
  signal?: AbortSignal | undefined;
  cwd?: string | undefined;
  secrets?: readonly string[] | undefined;
  onStdout?: (data: Buffer) => void;
  onStderr?: (data: Buffer) => void;
}): Promise<{ receipt: HttpEvidenceReceipt; stdout: string; stderr: string }> {
  validateCurlCaptureArguments(args.curlArguments);
  const timeout = args.timeoutSeconds ?? 120;
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 600)
    throw new Error('HTTP capture timeout must be between 1 and 600 seconds');
  if (args.signal?.aborted) throw new Error('HTTP evidence request cancelled before sending');
  const directory = path.join(args.deliverablesDir, 'http-exchanges', args.findingId);
  if (!/^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(args.findingId))
    throw new Error('Invalid HTTP evidence finding ID');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = await mkdtemp(path.join(directory, '.capture-'));
  const tracePath = path.join(temporary, 'curl.trace');
  const invocation = await snapshotCurlInvocation(args.curlArguments, args.cwd ?? process.cwd(), timeout, args.secrets);
  const stdout: Buffer[] = [],
    stderr: Buffer[] = [];
  let stdoutLength = 0,
    stderrLength = 0;
  // Tool output is bounded; the on-disk trace keeps every captured byte.
  const limit = 32 * 1024;
  const collect = (buffers: Buffer[], data: Buffer, length: number) => {
    if (length < limit) buffers.push(data.subarray(0, limit - length));
    return length + data.length;
  };
  try {
    const child = spawn('curl', ['--disable', ...args.curlArguments, '--trace', tracePath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
      ...(args.cwd ? { cwd: args.cwd } : {}),
    });
    child.stdout.on('data', (data: Buffer) => {
      args.onStdout?.(data);
      stdoutLength = collect(stdout, data, stdoutLength);
    });
    child.stderr.on('data', (data: Buffer) => {
      args.onStderr?.(data);
      stderrLength = collect(stderr, data, stderrLength);
    });
    let interrupted = false;
    const stop = () => {
      interrupted = true;
      try {
        if (child.pid && process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
      }
    };
    const timer = setTimeout(stop, timeout * 1000);
    args.signal?.addEventListener('abort', stop, { once: true });
    if (args.signal?.aborted) stop();
    const exitCode = await new Promise<number>((resolve) => {
      child.once('error', () => resolve(127));
      child.once('close', (code) => resolve(interrupted ? 124 : (code ?? 128)));
    }).finally(() => {
      clearTimeout(timer);
      args.signal?.removeEventListener('abort', stop);
    });
    let trace = '';
    try {
      trace = await readFile(tracePath, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    for (const input of invocation.inputs) {
      if (input.base64 === undefined) continue;
      try {
        if (!(await readFile(input.path)).equals(Buffer.from(input.base64, 'base64')))
          invocation.manual_reasons.push(`Input changed during capture: ${input.path}`);
      } catch {
        invocation.manual_reasons.push(`Input became unreadable during capture: ${input.path}`);
      }
    }
    const receipt = await persistCapturedTrace({
      deliverablesDir: args.deliverablesDir,
      findingId: args.findingId,
      trace,
      exitCode,
      invocation,
    });
    const output = (buffers: Buffer[], length: number) =>
      Buffer.concat(buffers).toString('utf8') +
      (length > limit ? '\n[Tool output truncated; full HTTP content is in the evidence file.]' : '');
    return { receipt, stdout: output(stdout, stdoutLength), stderr: output(stderr, stderrLength) };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
