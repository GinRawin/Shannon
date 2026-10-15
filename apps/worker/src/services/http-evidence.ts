// Copyright (C) 2026 Keygraph, Inc.
// Join actual curl traces and host-verified HTTP replay plans into report outputs.

import { chmod, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { AddFindingInput, AdditionalSection, StepItem } from '../collectors/finding-collector.js';
import { REPRODUCTION_SCRIPT_FILENAME } from '../paths.js';
import type { Credentials } from '../types/config.js';
import type { ReconciliationClass } from '../types/reconciliation.js';
import { ALL_RECONCILIATION_CLASSES } from '../types/reconciliation.js';
import { type HttpEvidenceReceipt, readVerifiedHttpEvidence } from './capture-http-request.js';
import { readCommittedFile } from './git-manager.js';
import type { ParsedHttpTrace } from './http-capture.js';
import { parseCurlTrace } from './http-capture.js';
import type { HttpReplayPlan, HttpReplayVerification } from './http-replay.js';
import { HTTP_REPLAY_PYTHON, hasVerifiedReplay } from './http-replay.js';

interface CapturedExchange extends ParsedHttpTrace {
  captured_at: string;
  exit_code: number;
  file: string;
  trace: string;
  capture_id?: string;
}
interface ReplayEntry {
  status?: string;
  vulnerability_id?: string;
  title?: string;
  http_replay?: HttpReplayPlan | null;
  http_replay_verification?: HttpReplayVerification;
  http_evidence_unavailable_reason?: string;
}
export interface CaptureRedaction {
  value: string;
  placeholder: string;
}

/** Report projections redact configured login values; private trace files remain unchanged. */
export function configuredCaptureRedactions(credentials?: Credentials): CaptureRedaction[] {
  if (!credentials) return [];
  const result: CaptureRedaction[] = [];
  const add = (value: string | undefined, placeholder: string) => {
    if (!value) return;
    for (const variant of new Set([value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1)])) {
      result.push({ value: variant, placeholder });
    }
  };
  add(credentials.username, '$username');
  add(credentials.password, '$password');
  add(credentials.totp_secret, '$totp');
  add(credentials.email_login?.address, '$email');
  add(credentials.email_login?.password, '$email_password');
  add(credentials.email_login?.totp_secret, '$email_totp');
  if (credentials.password)
    add(
      Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64'),
      '[configured Basic authentication]',
    );
  return result.sort((a, b) => b.value.length - a.value.length);
}

async function committedJson<T>(dir: string, file: string): Promise<T | undefined> {
  const result = await readCommittedFile(dir, file);
  if (result.state === 'absent') return undefined;
  if (result.state !== 'present') throw new Error(`HTTP evidence input is unreadable: ${file}`);
  return JSON.parse(result.contents) as T;
}

async function loadTaskToFindingIds(dir: string): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  for (const vulnClass of ALL_RECONCILIATION_CLASSES) {
    const map = await committedJson<{ map?: Record<string, string> }>(dir, `${vulnClass}_renumber_map.json`);
    for (const [taskId, findingId] of Object.entries(map?.map ?? {})) {
      if (typeof findingId === 'string') result.set(taskId, findingId);
    }
  }
  return result;
}

async function loadExchanges(dir: string): Promise<Map<string, CapturedExchange[]>> {
  const root = path.join(dir, 'http-exchanges');
  const result = new Map<string, CapturedExchange[]>();
  const receiptsByTask = new Map<string, HttpEvidenceReceipt[]>();
  for (const vulnClass of ALL_RECONCILIATION_CLASSES) {
    const entries = await committedJson<
      Array<{ vulnerability_id: string; http_evidence_receipts?: HttpEvidenceReceipt[] }>
    >(dir, `${vulnClass}_exploit_collector.json`);
    for (const entry of entries ?? []) {
      // Presence (including []) marks the new enforced path. Legacy runs remain readable.
      if (entry.http_evidence_receipts !== undefined)
        receiptsByTask.set(entry.vulnerability_id, entry.http_evidence_receipts);
    }
  }
  let taskDirs: string[];
  try {
    taskDirs = await readdir(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') taskDirs = [];
    else throw error;
  }
  for (const taskId of taskDirs.filter((id) => /^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(id)).sort()) {
    if (receiptsByTask.has(taskId)) continue;
    const taskDir = path.join(root, taskId);
    for (const file of (await readdir(taskDir)).filter((name) => name.endsWith('.json')).sort()) {
      const stored = JSON.parse(await readFile(path.join(taskDir, file), 'utf8')) as {
        finding_id?: string;
        captured_at?: string;
        exit_code?: number;
        trace?: string;
      };
      if (stored.finding_id !== taskId || typeof stored.trace !== 'string' || typeof stored.captured_at !== 'string') {
        throw new Error(`Invalid HTTP capture: ${taskId}/${file}`);
      }
      // Decode the trace again, including legacy captures whose stored parsed strings were wrong.
      const list = result.get(taskId) ?? [];
      list.push({
        ...parseCurlTrace(stored.trace),
        trace: stored.trace,
        captured_at: stored.captured_at,
        exit_code: stored.exit_code ?? -1,
        file: `http-exchanges/${taskId}/${file}`,
      });
      result.set(taskId, list);
    }
    result
      .get(taskId)
      ?.sort((a, b) => Date.parse(a.captured_at) - Date.parse(b.captured_at) || a.file.localeCompare(b.file));
  }
  for (const [taskId, receipts] of receiptsByTask) {
    const captures: CapturedExchange[] = [];
    for (const receipt of receipts) {
      if (receipt.finding_id !== taskId) throw new Error('HTTP evidence belongs to a different vulnerability');
      const stored = await readVerifiedHttpEvidence(dir, receipt);
      captures.push({
        ...stored,
        file: receipt.file,
        errors: receipt.complete ? stored.errors : [...stored.errors, 'Incomplete HTTP transfer'],
      });
    }
    result.set(taskId, captures);
  }
  return result;
}

/** The model sees counts and file references; exact HTTP evidence is joined by the host later. */
export async function renderCapturedHttpEvidence(
  dir: string,
  vulnClass: ReconciliationClass,
  taskToFinding: ReadonlyMap<string, string>,
): Promise<string> {
  const exchanges = await loadExchanges(dir);
  const prefix = {
    injection: 'INJ-',
    xss: 'XSS-',
    auth: 'AUTH-',
    authz: 'AUTHZ-',
    ssrf: 'SSRF-',
    miscellaneous: 'MISC-',
  }[vulnClass];
  const lines: string[] = [];
  for (const [taskId, findingId] of taskToFinding) {
    if (!taskId.startsWith(prefix)) continue;
    const captures = exchanges.get(taskId) ?? [];
    if (captures.length)
      lines.push(
        `- ${findingId}: ${captures.length} captured HTTP evidence record(s). The host will attach their request/response evidence.`,
      );
  }
  return lines.length ? `## Captured HTTP Evidence Index\n\n${lines.join('\n')}\n` : '';
}

function redactBytes(original: Buffer, redactions: readonly CaptureRedaction[]): Buffer {
  const needles = redactions
    .filter((redaction) => redaction.value)
    .map((redaction) => ({
      needle: Buffer.from(redaction.value),
      replacement: Buffer.from(redaction.placeholder),
    }));
  const pieces: Buffer[] = [];
  let start = 0;
  while (start < original.length) {
    let match: (typeof needles)[number] | undefined;
    let position = original.length;
    for (const candidate of needles) {
      const index = original.indexOf(candidate.needle, start);
      if (
        index >= 0 &&
        (index < position || (index === position && candidate.needle.length > (match?.needle.length ?? 0)))
      ) {
        position = index;
        match = candidate;
      }
    }
    if (!match) break;
    pieces.push(original.subarray(start, position), match.replacement);
    start = position + match.needle.length;
  }
  pieces.push(original.subarray(start));
  return Buffer.concat(pieces);
}

function displayBytes(base64: string, redactions: readonly CaptureRedaction[]): string {
  const original = Buffer.from(base64, 'base64');
  const separator = original.indexOf('\r\n\r\n');
  const variants = new Map(
    redactions.filter((redaction) => redaction.value).map((redaction) => [redaction.value, redaction.placeholder]),
  );
  const pattern = [...variants.keys()]
    .sort((a, b) => b.length - a.length)
    .map((value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|');
  const mask = (value: string) =>
    pattern ? value.replace(new RegExp(pattern, 'g'), (match) => variants.get(match) as string) : value;
  let header = '';
  let body: Buffer = original;
  if (
    separator >= 0 &&
    Buffer.from(original.subarray(0, separator).toString('utf8')).equals(original.subarray(0, separator))
  ) {
    header = `${original
      .subarray(0, separator)
      .toString('utf8')
      .split('\r\n')
      .map((line, index) => {
        // Preserve endpoint paths, field names, and the actual session tokens/cookies.
        if (index === 0) return line.replace(/=([^& \r\n]*)/g, (_match, value: string) => `=${mask(value)}`);
        const split = line.indexOf(':');
        if (split < 0) return line;
        const name = line.slice(0, split),
          value = line.slice(split + 1);
        if (/^(?:cookie|set-cookie)$/i.test(name) || (/authorization$/i.test(name) && /^\s*Bearer\s/i.test(value)))
          return line;
        if (/authorization$/i.test(name) && /^\s*Basic\s/i.test(value)) {
          const token = value.trim().replace(/^Basic\s+/i, '');
          const basic = redactions.find(
            (redaction) => redaction.placeholder === '[configured Basic authentication]' && redaction.value === token,
          );
          return basic ? `${name}: Basic ${basic.placeholder}` : line;
        }
        const literal = redactions.find((redaction) => value.trim() === redaction.value);
        return literal ? `${name}: ${literal.placeholder}` : line;
      })
      .join('\r\n')}\r\n\r\n`;
    body = original.subarray(separator + 4);
  }
  const decoded = body.toString('utf8');
  if (Buffer.from(decoded).equals(body)) {
    try {
      JSON.parse(decoded);
      // Change JSON values without changing field names, formatting, or unaffected strings.
      body = Buffer.from(
        decoded.replace(/"(?:\\.|[^"\\])*"/g, (token, offset: number) => {
          if (/^\s*:/.test(decoded.slice(offset + token.length))) return token;
          const value = JSON.parse(token) as string;
          const projected = mask(value);
          return projected === value ? token : JSON.stringify(projected);
        }),
      );
    } catch {
      body = /content-type:\s*application\/x-www-form-urlencoded/i.test(header)
        ? Buffer.from(
            decoded.replace(
              /(^|&)([^=&]+)=([^&]*)/g,
              (_match, prefix: string, key: string, value: string) => `${prefix}${key}=${mask(value)}`,
            ),
          )
        : redactBytes(body, redactions);
    }
  } else body = redactBytes(body, redactions);
  const text = body.toString('utf8');
  return (
    header +
    (Buffer.from(text).equals(body) && !body.some((byte) => byte < 32 && ![9, 10, 13].includes(byte))
      ? text
      : `[Binary HTTP data; base64]\n${body.toString('base64')}`)
  );
}

function httpSection(
  captures: readonly CapturedExchange[],
  redactions: readonly CaptureRedaction[],
): AdditionalSection {
  const items: StepItem[] = [
    {
      kind: 'prose',
      text: '以下为 curl 实际收发的 HTTP 应用层数据。配置的登录凭据在报告展示中使用占位符；原始 trace 与字节记录保存在内部证据文件中。重定向等多个往返分别展示，二进制内容以 Base64 展示。',
    },
  ];
  for (const [index, capture] of captures.entries()) {
    items.push({
      kind: 'prose',
      text: `调用 ${index + 1}，捕获于 ${capture.captured_at}，curl 退出码 ${capture.exit_code}，${capture.capture_id ? `采集 ID：${capture.capture_id}，` : ''}证据文件：${capture.file}。`,
    });
    if (capture.errors.length) {
      items.push({
        kind: 'prose',
        text: '此记录不完整，不能作为完整 HTTP 往返证据。内部证据文件保留已捕获内容及失败状态。',
      });
    }
    for (const [pairIndex, exchange] of capture.exchanges.entries()) {
      items.push({ kind: 'prose', text: `HTTP 往返 ${pairIndex + 1}。` });
      if (exchange.request_base64)
        items.push(
          { kind: 'prose', text: '请求：' },
          { kind: 'code', block: { language: 'http', content: displayBytes(exchange.request_base64, redactions) } },
        );
      if (exchange.response_base64)
        items.push(
          { kind: 'prose', text: '响应：' },
          { kind: 'code', block: { language: 'http', content: displayBytes(exchange.response_base64, redactions) } },
        );
    }
    if (capture.exchanges.length === 0) items.push({ kind: 'prose', text: '此次调用未捕获到 HTTP 请求或响应。' });
  }
  return { heading: '捕获的 HTTP 请求与响应', items };
}

async function loadReplayEntries(dir: string): Promise<ReplayEntry[]> {
  const entries: ReplayEntry[] = [];
  for (const vulnClass of ALL_RECONCILIATION_CLASSES) {
    const collected = await committedJson<ReplayEntry[]>(dir, `${vulnClass}_exploit_collector_renumbered.json`);
    if (collected !== undefined && !Array.isArray(collected)) throw new Error(`Invalid replay collector: ${vulnClass}`);
    entries.push(...(collected ?? []));
  }
  return entries;
}

export async function attachHttpEvidence(
  findings: readonly AddFindingInput[],
  deliverablesDir: string,
  redactions: readonly CaptureRedaction[] = [],
): Promise<AddFindingInput[]> {
  const taskToFinding = await loadTaskToFindingIds(deliverablesDir);
  const taskByFinding = new Map([...taskToFinding].map(([task, finding]) => [finding, task]));
  const capturesByTask = await loadExchanges(deliverablesDir);
  const entries = await loadReplayEntries(deliverablesDir);
  const entriesByFinding = new Map(entries.map((entry) => [entry.vulnerability_id, entry]));
  const verifiedIds = new Set(
    entries
      .filter((entry) => entry.status === 'exploited' && hasVerifiedReplay(entry))
      .map((entry) => entry.vulnerability_id),
  );
  return findings.map((finding) => {
    const task = taskByFinding.get(finding.finding_id);
    const captures = task ? (capturesByTask.get(task) ?? []) : [];
    const complete = captures.some(
      (capture) =>
        !capture.errors.length &&
        capture.exchanges.some((exchange) => exchange.request_base64 && exchange.response_base64),
    );
    const coverage: AdditionalSection = {
      heading: '自动化重放覆盖',
      items: [
        {
          kind: 'prose',
          text: verifiedIds.has(finding.finding_id)
            ? `此漏洞已通过宿主执行的 HTTP 影响断言和清理检查，包含在 ${REPRODUCTION_SCRIPT_FILENAME} 中。执行时会重新检查相同断言，失败时返回非零退出码。`
            : `此漏洞未提供通过宿主验证的 HTTP 重放方案，不包含在 ${REPRODUCTION_SCRIPT_FILENAME} 中。未验证的旧版 Bash 脚本也不会执行。`,
        },
        {
          kind: 'prose',
          text: complete
            ? '已附上通过 HTTP 捕获工具记录的请求与响应。'
            : `缺少已关联的完整 HTTP 往返证据。${entriesByFinding.get(finding.finding_id)?.http_evidence_unavailable_reason ?? '请查看内部采集文件和其他利用证据。'}`,
        },
      ],
    };
    return {
      ...finding,
      additional_sections: [
        ...(finding.additional_sections ?? []).filter(
          (section) => !['捕获的 HTTP 请求与响应', '自动化重放覆盖'].includes(section.heading),
        ),
        ...(captures.length ? [httpSection(captures, redactions)] : []),
        coverage,
      ],
    };
  });
}

export async function writeReproductionScript(
  dir: string,
  targetUrl: string,
  includedFindingIds: ReadonlySet<string>,
): Promise<string> {
  const entries = (await loadReplayEntries(dir)).filter(
    (entry) =>
      entry.status === 'exploited' &&
      typeof entry.vulnerability_id === 'string' &&
      includedFindingIds.has(entry.vulnerability_id) &&
      hasVerifiedReplay(entry),
  );
  entries.sort((a, b) => (a.vulnerability_id as string).localeCompare(b.vulnerability_id as string));
  const recipes = entries.map((entry) => ({
    finding_id: entry.vulnerability_id,
    base_url: targetUrl,
    plan: entry.http_replay,
  }));
  const lines = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'umask 077',
    '# Requires Bash, Python 3 and curl. Export authentication values before running.',
    // biome-ignore lint/suspicious/noTemplateCurlyInString: These variables are expanded by the generated Bash script.
    'export BASE_URL="${BASE_URL:-}" BEARER_TOKEN="${BEARER_TOKEN:-}" COOKIE="${COOKIE:-}"',
    // biome-ignore lint/suspicious/noTemplateCurlyInString: These variables are expanded by the generated Bash script.
    'export USERNAME="${USERNAME:-}" PASSWORD="${PASSWORD:-}" OTP="${OTP:-}"',
    // biome-ignore lint/suspicious/noTemplateCurlyInString: These variables are expanded by the generated Bash script.
    'mkdir -p "${OUTPUT_DIR:-./shannon-replay-results}"',
    // biome-ignore lint/suspicious/noTemplateCurlyInString: These variables are expanded by the generated Bash script.
    'export OUTPUT_DIR="$(mktemp -d "${OUTPUT_DIR:-./shannon-replay-results}/run-XXXXXXXX")"',
    '# Included findings (host verified; impact predicates must still match the target):',
    ...entries.map((entry) => `# ${entry.vulnerability_id}: ${(entry.title ?? '').replace(/[\r\n]/g, ' ')}`),
    ...(entries.length ? [] : ['# No verified HTTP replay plans. This script exits with status 1.']),
    'echo "HTTP replay results: $OUTPUT_DIR"',
    "python3 - <<'SHANNON_HTTP_REPLAY_PY'",
    HTTP_REPLAY_PYTHON,
    `sys.exit(run(json.loads(${JSON.stringify(JSON.stringify(recipes))})))`,
    'SHANNON_HTTP_REPLAY_PY',
    '',
  ];
  const scriptPath = path.join(dir, REPRODUCTION_SCRIPT_FILENAME);
  await mkdir(dir, { recursive: true });
  await writeFile(scriptPath, lines.join('\n'), { mode: 0o700 });
  await chmod(scriptPath, 0o700);
  return scriptPath;
}
