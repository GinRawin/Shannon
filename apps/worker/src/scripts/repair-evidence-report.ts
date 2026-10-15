#!/usr/bin/env node
import { execFile } from 'node:child_process';
// Offline, explicitly reviewed migration. Never launches a scanner, browser, curl, or replay.
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import type { AddExploitInput } from '../collectors/exploit-collector.js';
import { type CapturedHttpRecord, persistCapturedTrace } from '../services/capture-http-request.js';
import { type CurlInvocation, snapshotCurlInvocation } from '../services/curl-invocation.js';
import { attachHttpEvidence } from '../services/http-evidence.js';
import { finalizeReport } from '../services/report-finalization.js';
import type { ReportData } from '../services/report-renderer.js';
import { ALL_RECONCILIATION_CLASSES } from '../types/reconciliation.js';

interface Decision {
  verification_method: 'http' | 'browser' | 'mixed' | 'other';
  http_evidence_display: 'include' | 'omit';
  http_evidence_reason: string;
  source_files: string[];
  proof_excerpt?: string;
  report_step_indices?: number[];
  recovered_commands?: Record<
    string,
    { argv: string[]; cwd: string; log: string; line: number; command_sha256: string }
  >;
}
const argv = process.argv.slice(2);
function option(name: string): string {
  const value = argv[argv.indexOf(name) + 1];
  if (!argv.includes(name) || !value) throw new Error(`Required: ${name}`);
  return value;
}
const source = await realpath(option('--source'));
const sourceReport = path.resolve(option('--report'));
const output = path.resolve(option('--output'));
if (output === source || source.startsWith(`${output}${path.sep}`) || output.startsWith(`${source}${path.sep}`))
  throw new Error('Output must be separate from the original deliverables.');
const decisionsPath = path.resolve(option('--decisions'));
const decisions = JSON.parse(await readFile(decisionsPath, 'utf8')) as Record<string, Decision>;
const report = JSON.parse(await readFile(sourceReport, 'utf8')) as ReportData;
const included = new Set(report.findings.map((finding) => finding.finding_id));
if (Object.keys(decisions).length !== included.size || [...included].some((id) => !decisions[id]))
  throw new Error('Provide exactly one reviewed decision for every retained finding.');
await mkdir(output, { mode: 0o700 }); // Deliberately refuses to overwrite any existing report.
const dir = path.join(output, '.evidence');
await mkdir(dir, { mode: 0o700 });
const files: string[] = [],
  revision: Array<Record<string, unknown>> = [];
const writeJson = async (name: string, value: unknown) => {
  await writeFile(path.join(dir, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  files.push(name);
};
const sha256 = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const git = promisify(execFile);
for (const klass of ALL_RECONCILIATION_CLASSES) {
  const collectorName = `${klass}_exploit_collector.json`,
    mapName = `${klass}_renumber_map.json`;
  let entries: AddExploitInput[], mapping: { map: Record<string, string> };
  try {
    entries = JSON.parse(await readFile(path.join(source, collectorName), 'utf8'));
    mapping = JSON.parse(await readFile(path.join(source, mapName), 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
    throw error;
  }
  const revised: AddExploitInput[] = [],
    renumbered: AddExploitInput[] = [];
  for (const entry of entries) {
    const findingId = mapping.map[entry.vulnerability_id];
    if (!findingId || !included.has(findingId)) continue;
    const decision = decisions[findingId];
    if (
      !decision ||
      !['http', 'browser', 'mixed', 'other'].includes(decision.verification_method) ||
      !['include', 'omit'].includes(decision.http_evidence_display) ||
      !decision.http_evidence_reason.trim()
    )
      throw new Error(`Invalid evidence decision for ${findingId}`);
    if ((decision.http_evidence_display === 'omit') !== (decision.source_files.length === 0))
      throw new Error(`Evidence decision/files disagree for ${findingId}`);
    const updated = structuredClone(entry);
    updated.verification_method = decision.verification_method;
    updated.http_evidence_display = decision.http_evidence_display;
    updated.http_evidence_reason = decision.http_evidence_reason;
    updated.http_evidence_ids = [];
    updated.http_evidence_receipts = [];
    updated.reproduction_capture_ids = [];
    const imports = [];
    for (const filename of decision.source_files) {
      if (!/^exchange-[a-zA-Z0-9-]+\.json$/.test(filename)) throw new Error('Invalid historical capture filename');
      const relative = `http-exchanges/${entry.vulnerability_id}/${filename}`;
      const capturePath = await realpath(path.join(source, relative));
      if (!capturePath.startsWith(`${source}${path.sep}`)) throw new Error('Historical input escapes source directory');
      const raw = await readFile(capturePath);
      const stored = JSON.parse(raw.toString()) as CapturedHttpRecord;
      if (stored.finding_id !== entry.vulnerability_id || typeof stored.trace !== 'string')
        throw new Error('Historical capture belongs to a different finding');
      const recovered = decision.recovered_commands?.[filename];
      let invocation: CurlInvocation | undefined = stored.invocation;
      if (recovered) {
        const line = (await readFile(recovered.log, 'utf8')).split(/\r?\n/)[recovered.line - 1];
        const data = line?.match(/\] bash: (\{.*\})$/)?.[1];
        if (!data || sha256(JSON.parse(data).command) !== recovered.command_sha256)
          throw new Error('Recovered command log checksum mismatch');
        invocation = await snapshotCurlInvocation(recovered.argv, recovered.cwd, 120);
        // Files found today cannot attest to their historical bytes.
        if (invocation.inputs.length) {
          invocation.inputs = [];
          invocation.manual_reasons.push('Historical input file bytes were not recorded at execution time.');
        }
      }
      const receipt = await persistCapturedTrace({
        deliverablesDir: dir,
        findingId: entry.vulnerability_id,
        trace: stored.trace,
        exitCode: stored.exit_code,
        capturedAt: stored.captured_at,
        ...(invocation ? { invocation } : {}),
        provenance: {
          kind: 'historical_import',
          original_file: relative,
          sha256: sha256(raw),
          ...(recovered ? { command_log: `${recovered.log}:${recovered.line}` } : {}),
        },
      });
      updated.http_evidence_ids.push(receipt.capture_id);
      updated.http_evidence_receipts.push(receipt);
      updated.reproduction_capture_ids.push(receipt.capture_id);
      imports.push({
        original_file: relative,
        original_sha256: sha256(raw),
        capture_id: receipt.capture_id,
        command_recovered: !!invocation,
      });
    }
    if (updated.status === 'exploited') {
      delete updated.http_replay;
      delete updated.http_replay_verification;
      delete updated.reproduction_script;
      if (decision.proof_excerpt) {
        if (!updated.proof_of_impact.includes(decision.proof_excerpt))
          throw new Error('Verification excerpt must come verbatim from the original evidence.');
        updated.proof_of_impact = decision.proof_excerpt;
      }
    }
    const finding = report.findings.find((item) => item.finding_id === findingId);
    if (finding && decision.report_step_indices)
      finding.exploitation_steps = decision.report_step_indices.map((index) => {
        const step = finding.exploitation_steps?.[index];
        if (!step) throw new Error('Invalid original step index');
        return step;
      });
    revised.push(updated);
    renumbered.push({ ...updated, vulnerability_id: findingId });
    revision.push({
      finding_id: findingId,
      source_id: entry.vulnerability_id,
      ...decision,
      recovered_commands: undefined,
      imports,
    });
  }
  await writeJson(collectorName, revised);
  await writeJson(`${klass}_exploit_collector_renumbered.json`, renumbered);
  await writeJson(mapName, mapping);
}
const env = {
  ...process.env,
  GIT_AUTHOR_NAME: 'Shannon offline evidence repair',
  GIT_AUTHOR_EMAIL: 'offline@shannon.invalid',
  GIT_COMMITTER_NAME: 'Shannon offline evidence repair',
  GIT_COMMITTER_EMAIL: 'offline@shannon.invalid',
};
if (new Set(revision.map((item) => item.finding_id)).size !== included.size)
  throw new Error('Some retained findings could not be matched to their original exploit collectors.');
await git('git', ['init', dir]);
await git('git', ['-C', dir, 'config', 'user.name', env.GIT_AUTHOR_NAME]);
await git('git', ['-C', dir, 'config', 'user.email', env.GIT_AUTHOR_EMAIL]);
await git('git', ['-C', dir, 'add', '--', ...files]);
await git('git', ['-C', dir, 'commit', '-m', 'Import explicitly reviewed historical evidence'], { env });
const assembled = { ...report, findings: await attachHttpEvidence(report.findings, dir) };
await writeJson('report.json', assembled);
await git('git', ['-C', dir, 'add', '--', 'report.json']);
await git('git', ['-C', dir, 'commit', '-m', 'Assemble corrected evidence report offline'], { env });
const finalized = await finalizeReport({
  deliverablesDir: dir,
  exploit: true,
  partialReasons: [],
  reportConfig: { sarif: true },
  workspaceName: 'offline-evidence-repair',
  logger: { info: console.log, warn: console.warn, error: console.error },
  ...(argv.includes('--no-pdf')
    ? {
        renderPdf: async () => {
          throw new Error('PDF deliberately disabled for local checks');
        },
      }
    : {}),
});
for (const filename of [
  'report.json',
  'report.sarif',
  'reproduce.sh',
  'comprehensive_security_assessment_report.md',
  ...(finalized.pdfGenerated ? ['comprehensive_security_assessment_report.pdf'] : []),
])
  await copyFile(path.join(dir, filename), path.join(output, filename));
await copyFile(decisionsPath, path.join(dir, 'evidence-decisions.private.json'));
await writeFile(
  path.join(output, 'evidence-decisions.json'),
  `${JSON.stringify(
    Object.fromEntries(
      Object.entries(decisions).map(([id, decision]) => [
        id,
        {
          ...decision,
          recovered_commands: decision.recovered_commands
            ? Object.fromEntries(
                Object.entries(decision.recovered_commands).map(([file, command]) => [
                  file,
                  { log: command.log, line: command.line, command_sha256: command.command_sha256 },
                ]),
              )
            : undefined,
        },
      ]),
    ),
    null,
    2,
  )}\n`,
  { mode: 0o600 },
);
await writeFile(
  path.join(output, 'revision.json'),
  `${JSON.stringify({ source, source_report: sourceReport, source_report_sha256: sha256(await readFile(sourceReport)), network_requests_sent: 0, pdf_generated: finalized.pdfGenerated, findings: revision }, null, 2)}\n`,
  { mode: 0o600 },
);
console.log(
  JSON.stringify({ output, findings: included.size, pdf_generated: finalized.pdfGenerated, network_requests_sent: 0 }),
);
