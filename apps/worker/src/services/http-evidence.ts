// Copyright (C) 2026 Keygraph, Inc.
// Join actual curl traces and host-verified HTTP replay plans into report outputs.

import type { AddFindingInput, AdditionalSection, StepItem } from '../collectors/finding-collector.js';
import { REPRODUCTION_SCRIPT_FILENAME } from '../paths.js';
import type { Credentials } from '../types/config.js';
import type { ReconciliationClass } from '../types/reconciliation.js';
import { ALL_RECONCILIATION_CLASSES } from '../types/reconciliation.js';
import { type HttpEvidenceReceipt, readVerifiedHttpEvidence } from './capture-http-request.js';
import { readCommittedFile } from './git-manager.js';
import type { ParsedHttpTrace } from './http-capture.js';
import type { HttpReplayPlan, HttpReplayVerification } from './http-replay.js';
import { hasVerifiedReplay } from './http-replay.js';
import { writeManualReproductionScript } from './reproduction-script.js';

interface CapturedExchange extends ParsedHttpTrace {
  captured_at: string;
  exit_code: number;
  file: string;
  trace: string;
  capture_id?: string;
  provenance?: { kind: 'historical_import'; original_file: string; sha256: string; command_log?: string };
}
interface ReplayEntry {
  status?: string;
  vulnerability_id?: string;
  title?: string;
  http_replay?: HttpReplayPlan | null;
  http_replay_verification?: HttpReplayVerification;
  http_evidence_unavailable_reason?: string;
  verification_method?: string;
  http_evidence_display?: 'include' | 'omit';
  http_evidence_reason?: string;
  http_evidence_ids?: string[];
  http_evidence_receipts?: HttpEvidenceReceipt[];
  reproduction_capture_ids?: string[];
  proof_of_impact?: string;
  evidence_of_vulnerability?: string;
  exploitation_steps?: string[];
  browser_evidence_files?: string[];
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
  const result = new Map<string, CapturedExchange[]>();
  const receiptsByTask = new Map<string, HttpEvidenceReceipt[]>();
  for (const vulnClass of ALL_RECONCILIATION_CLASSES) {
    const entries = await committedJson<
      Array<{
        vulnerability_id: string;
        http_evidence_receipts?: HttpEvidenceReceipt[];
        http_evidence_ids?: string[];
        http_evidence_display?: string;
      }>
    >(dir, `${vulnClass}_exploit_collector.json`);
    for (const entry of entries ?? []) {
      // No filesystem inference, including for legacy runs. Display is an explicit agent choice.
      receiptsByTask.set(
        entry.vulnerability_id,
        entry.http_evidence_display === 'include'
          ? (entry.http_evidence_receipts ?? []).filter((receipt) =>
              entry.http_evidence_ids?.includes(receipt.capture_id),
            )
          : [],
      );
    }
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

/** Preserve the original observations while converting fenced blocks for both report renderers. */
export function evidenceMarkdownItems(markdown: string): StepItem[] {
  const items: StepItem[] = [];
  const fence = /^(`{3,}|~{3,})([^\n]*)\n([\s\S]*?)^\1[ \t]*$/gm;
  let cursor = 0;
  for (const match of markdown.matchAll(fence)) {
    const prose = markdown.slice(cursor, match.index).trim();
    if (prose) items.push({ kind: 'prose', text: prose });
    items.push({
      kind: 'code',
      block: { language: match[2]?.trim() || 'text', content: (match[3] ?? '').replace(/\n$/, '') },
    });
    cursor = (match.index ?? 0) + match[0].length;
  }
  const prose = markdown.slice(cursor).trim();
  if (prose) items.push({ kind: 'prose', text: prose });
  return items;
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
    if (capture.provenance)
      items.push({
        kind: 'prose',
        text: `历史证据离线导入，未重新发送请求。原文件：${capture.provenance.original_file}；SHA-256：${capture.provenance.sha256}。`,
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
    const entry = entriesByFinding.get(finding.finding_id);
    const display = entry?.http_evidence_display ?? 'unreviewed';
    if (
      display === 'include' &&
      (!entry?.http_evidence_ids?.length || captures.length !== entry.http_evidence_ids.length)
    )
      throw new Error(`Selected HTTP evidence is unavailable for ${finding.finding_id}`);
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
            ? `此漏洞有通过宿主验证的 HTTP 影响断言，可使用 ${REPRODUCTION_SCRIPT_FILENAME} --verify ${finding.finding_id} 显式执行。普通命令复验与影响断言分别记录。`
            : `此漏洞没有自动化影响断言。使用 ${REPRODUCTION_SCRIPT_FILENAME} --show ${finding.finding_id} 查看实际采集调用或人工复验步骤；命令执行完成不代表漏洞影响已自动验证。`,
        },
        {
          kind: 'prose',
          text:
            display === 'omit'
              ? `根据利用验证方式，本报告不展示 HTTP 数据包。${entry?.http_evidence_reason ?? entry?.http_evidence_unavailable_reason ?? ''}`
              : display === 'unreviewed'
                ? '此旧记录尚未明确选择 HTTP 展示证据；未自动附加目录中的采集文件。'
                : complete
                  ? '已附上通过 HTTP 捕获工具记录的请求与响应。'
                  : `缺少已关联的完整 HTTP 往返证据。${entriesByFinding.get(finding.finding_id)?.http_evidence_unavailable_reason ?? '请查看内部采集文件和其他利用证据。'}`,
        },
      ],
    };
    return {
      ...finding,
      http_evidence_display: display,
      ...(entry?.verification_method ? { verification_method: entry.verification_method } : {}),
      additional_sections: [
        ...(finding.additional_sections ?? []).filter(
          (section) =>
            !['捕获的 HTTP 请求与响应', '自动化重放覆盖', '浏览器验证证据', '验证证据', '证据选择'].includes(
              section.heading,
            ),
        ),
        ...(display === 'include' && captures.length ? [httpSection(captures, redactions)] : []),
        ...(entry &&
        (display !== 'include' || entry.verification_method !== 'http') &&
        (entry.proof_of_impact || entry.evidence_of_vulnerability)
          ? [
              {
                heading: ['browser', 'mixed'].includes(entry.verification_method ?? '') ? '浏览器验证证据' : '验证证据',
                items: evidenceMarkdownItems(
                  [
                    entry.proof_of_impact ?? entry.evidence_of_vulnerability ?? '',
                    ...(entry.browser_evidence_files ?? []).map((file) => `浏览器证据文件：${file}`),
                  ].join('\n\n'),
                ).map((item) => {
                  const mask = (value: string) =>
                    redactions.reduce(
                      (text, redaction) => text.split(redaction.value).join(redaction.placeholder),
                      value,
                    );
                  return item.kind === 'prose'
                    ? { ...item, text: mask(item.text) }
                    : { ...item, block: { ...item.block, content: mask(item.block.content) } };
                }),
              },
            ]
          : []),
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
  return writeManualReproductionScript(dir, await loadReplayEntries(dir), targetUrl, includedFindingIds);
}
