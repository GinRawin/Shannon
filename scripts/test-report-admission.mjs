// Offline regression: overlapping task/report IDs must not drop verified findings.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp('/tmp/shannon-report-admission-');
await run(process.execPath, [
  'node_modules/typescript/bin/tsc', '-p', 'apps/worker/tsconfig.json',
  '--outDir', `${temporary}/dist`, '--incremental', 'false',
], { cwd: root });
await symlink(`${root}/apps/worker/node_modules`, `${temporary}/node_modules`);
const load = (name) => import(pathToFileURL(`${temporary}/dist/${name}.js`));
const { persistCapturedTrace } = await load('services/capture-http-request');
const { loadPacketBackedFindingIds, attachHttpEvidence, writeReproductionScript } = await load('services/http-evidence');
const { compactReportFindings } = await load('services/compaction-core');
const { createFindingCollector } = await load('collectors/finding-collector');
const {
  aggregateRecordFailures, applyRecordRetryEvidence, finalizeRecordReportAdmission,
  loadRecordReportFindingIds, validateRecordReportAdmission, writeFinalRecordFailureAudit,
} = await load('services/record-verification');
const { assembleFinalReportWithEvidence } = await load('services/reporting');
const dir = `${temporary}/deliverables`;
await mkdir(dir);
const env = {
  ...process.env, GIT_AUTHOR_NAME: 'Report admission test', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
  GIT_COMMITTER_NAME: 'Report admission test', GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
};
async function commit(files) {
  for (const [name, value] of Object.entries(files)) {
    await writeFile(path.join(dir, name), `${JSON.stringify(value, null, 2)}\n`);
  }
  await run('git', ['add', '--', ...Object.keys(files)], { cwd: dir, env });
  await run('git', ['commit', '-m', 'Report admission fixture'], { cwd: dir, env });
}
function tracePart(label, value) {
  const bytes = Buffer.from(value);
  const lines = [`${label}, ${bytes.length} bytes (0x${bytes.length.toString(16)})`];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const hex = [...bytes.subarray(offset, offset + 16)].map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
    lines.push(`${offset.toString(16).padStart(4, '0')}: ${hex.padEnd(47)} fixture`);
  }
  return lines.join('\n');
}
async function captured(id, exitCode = 0) {
  const trace = [
    tracePart('=> Send header', `GET /${id} HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n`),
    tracePart('<= Recv header', 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'),
    tracePart('<= Recv data', `evidence-for-${id}`),
  ].join('\n');
  const receipt = await persistCapturedTrace({ deliverablesDir: dir, findingId: id, trace, exitCode });
  assert.equal(receipt.complete, exitCode === 0);
  return {
    status: 'exploited', vulnerability_id: id, title: id, verification_method: 'http',
    http_evidence_display: 'include', http_evidence_ids: [receipt.capture_id], http_evidence_receipts: [receipt],
  };
}
const injection = await captured('INJ-12');
const auth = await captured('AUTH-01');
const expansion = await captured('INJ-18');
const unqueued = await captured('INJ-99');
const incomplete = await captured('INJ-19', 1);
const omitted = (id) => ({ status: 'exploited', vulnerability_id: id, http_evidence_display: 'omit' });
const map = (klass, mapping) => ({ vulnerability_type: klass, map: mapping, order: Object.keys(mapping), excluded: [] });
await run('git', ['init'], { cwd: dir });
await commit({
  'injection_renumber_map.json': map('injection', { 'INJ-12': 'INJ-07', 'INJ-07': 'INJ-06' }),
  'injection_exploit_collector.json': [injection, omitted('INJ-07')],
  'injection_exploit_collector_renumbered.json': [{ ...injection, vulnerability_id: 'INJ-07' }, omitted('INJ-06')],
  'auth_renumber_map.json': map('auth', { 'AUTH-01': 'AUTH-02', 'AUTH-02': 'AUTH-03' }),
  'auth_exploit_collector.json': [auth, omitted('AUTH-02')],
  'auth_exploit_collector_renumbered.json': [{ ...auth, vulnerability_id: 'AUTH-02' }, omitted('AUTH-03')],
  'explore_candidates_injection.json': { vulnerabilities: [{ ID: 'INJ-18' }, { ID: 'INJ-19' }] },
  'explore_expansion_injection_exploit_collector.json': [expansion, incomplete, unqueued],
});

const ids = await loadPacketBackedFindingIds(dir);
assert.deepEqual([...ids].sort(), ['AUTH-02', 'INJ-07', 'INJ-18']);
console.log('PASS overlapping original and report IDs retain the verified injection and gateway finding');
console.log('PASS queued expansion is admitted; unqueued and incomplete evidence are excluded');

const recordIds = new Set(['AUTH-02', 'INJ-07', 'INJ-18']);
const collector = createFindingCollector(true, new Set([...recordIds].filter((id) => ids.has(id))));
const finding = (id) => ({
  finding_id: id, title: id, category: id.startsWith('AUTH') ? 'Authentication' : 'Injection', severity: 'high',
  status: 'exploited', overview: 'Fixture', impact: 'Fixture', remediation: 'Fixture',
  auth_state: 'None', prerequisites: 'None', vulnerable_location: '/fixture', owasp_category: 'A01:2025',
  exploitation_steps: [{ items: [{ kind: 'prose', text: 'Fixture' }] }],
});
for (const id of recordIds) {
  const result = await collector.tools[0].execute(`add-${id}`, finding(id));
  assert.equal(JSON.parse(result.content[0].text).status, 'success');
}
const denied = await collector.tools[0].execute('deny-unverified', finding('INJ-06'));
assert.equal(JSON.parse(denied.content[0].text).status, 'error');
const attached = await attachHttpEvidence(collector.getAll(), dir);
for (const [id, original] of [['INJ-07', 'INJ-12'], ['AUTH-02', 'AUTH-01'], ['INJ-18', 'INJ-18']]) {
  const item = attached.find((entry) => entry.finding_id === id);
  assert.match(JSON.stringify(item.additional_sections), new RegExp(`evidence-for-${original}`));
}
console.log('PASS report collector and attached packets use the correct original finding');

await commit({
  'report.json': {
    report_meta: { target: 'https://fixture.invalid', assessment_date: '2026-11-02', scope: 'Fixture', executive_summary: 'Fixture' },
    findings: attached.filter((item) => item.finding_id !== 'INJ-18'), reconciliation_failed: [],
  },
});
await compactReportFindings({
  deliverablesDir: dir, participatingClasses: ['injection', 'auth'], renumberFailedClasses: [],
  logger: { info() {}, warn() {}, error() {} },
});
assert.deepEqual([...(await loadPacketBackedFindingIds(dir))].sort(), ['AUTH-01', 'INJ-01', 'INJ-18']);
const compacted = await attachHttpEvidence([finding('INJ-01'), finding('AUTH-01')], dir);
assert.match(JSON.stringify(compacted[0].additional_sections), /evidence-for-INJ-12/);
assert.match(JSON.stringify(compacted[1].additional_sections), /evidence-for-AUTH-01/);
const script = await writeReproductionScript(dir, 'https://fixture.invalid', new Set(['INJ-01', 'AUTH-01']));
await run('bash', ['-n', script]);
console.log('PASS compaction and reproduction export preserve the correct evidence without target requests');

const admissionDir = `${temporary}/strict-admission`;
await mkdir(admissionDir);
await run('git', ['init'], { cwd: admissionDir });
async function admissionCapture(id) {
  const trace = [
    tracePart('=> Send header', `GET /${id} HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n`),
    tracePart('<= Recv header', 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'),
    tracePart('<= Recv data', `strict-${id}`),
  ].join('\n');
  return persistCapturedTrace({ deliverablesDir: admissionDir, findingId: id, trace, exitCode: 0 });
}
const strictInjectionReceipt = await admissionCapture('INJ-01');
const strictXssReceipt = await admissionCapture('XSS-01');
const strictEntry = (id, receipt) => ({
  status: 'exploited', vulnerability_id: id, title: id,
  severity: 'high', vulnerable_location: '/fixture', overview: 'Fixture', impact: 'Fixture',
  exploitation_steps: ['Replay the fixture'], proof_of_impact: 'Fixture proof',
  http_evidence_display: 'include', http_evidence_ids: [receipt.capture_id], http_evidence_receipts: [receipt],
});
const strictInjection = strictEntry('INJ-01', strictInjectionReceipt);
const strictXss = strictEntry('XSS-01', strictXssReceipt);
const strictVerdict = (id, receipt) => ({
  finding_id: id, status: 'verified', reason: 'fixture', capture_ids: [receipt.capture_id],
  frontend_status: 'unable_to_determine', frontend_url: null, frontend_trigger: null, frontend_reason: 'fixture',
  http_evidence_receipts: [receipt], stage: 'record',
});
const strictFiles = {
  'injection_renumber_map.json': map('injection', { 'INJ-01': 'INJ-01' }),
  'injection_exploit_collector.json': [strictInjection],
  'injection_exploit_collector_renumbered.json': [strictInjection],
  'xss_renumber_map.json': map('xss', { 'XSS-01': 'XSS-01' }),
  'xss_exploit_collector.json': [strictXss],
  'xss_exploit_collector_renumbered.json': [strictXss],
};
for (const [name, value] of Object.entries(strictFiles))
  await writeFile(path.join(admissionDir, name), `${JSON.stringify(value, null, 2)}\n`);
await run('git', ['add', '--', ...Object.keys(strictFiles)], { cwd: admissionDir, env });
await run('git', ['commit', '-m', 'Strict admission fixtures'], { cwd: admissionDir, env });
const verdictFile = path.join(admissionDir, 'record_verification.json');
await writeFile(verdictFile, `${JSON.stringify([
  strictVerdict('INJ-01', strictInjectionReceipt),
  strictVerdict('XSS-01', strictXssReceipt),
], null, 2)}\n`);
assert.deepEqual(await validateRecordReportAdmission(admissionDir), ['XSS-01: missing JavaScript execution evidence']);
await writeFile(verdictFile, `${JSON.stringify([
  strictVerdict('INJ-01', strictInjectionReceipt),
  {
    ...strictVerdict('XSS-01', strictXssReceipt),
    browser_verification: {
      assertion_type: 'document_title_contains', expected: 'marker', observed: 'marker', evidence_files: ['.shannon/scratchpad/xss.png'],
    },
  },
], null, 2)}\n`);
assert.deepEqual(await validateRecordReportAdmission(admissionDir), []);
await writeFile(verdictFile, `${JSON.stringify([{
  ...strictVerdict('XSS-01', strictXssReceipt),
  browser_verification: {
    assertion_type: 'dialog_text_contains', expected: 'marker', observed: 'marker', evidence_files: ['.shannon/scratchpad/xss.png'],
  },
}], null, 2)}\n`);
assert.deepEqual(await validateRecordReportAdmission(admissionDir), ['INJ-01: missing verified Record verdict']);
console.log('PASS strict admission blocks missing verdicts and XSS without JavaScript execution evidence');

// Exercise the repaired loop with overlapping source/report IDs and both initial and expansion failures.
const loopDir = `${temporary}/closed-loop`;
await mkdir(loopDir);
await run('git', ['init'], { cwd: loopDir });
const writeLoop = async (name, value) => writeFile(path.join(loopDir, name), `${JSON.stringify(value, null, 2)}\n`);
const readLoop = async (name) => JSON.parse(await readFile(path.join(loopDir, name), 'utf8'));
const retryTrace = [
  tracePart('=> Send header', 'GET /retry HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n'),
  tracePart('<= Recv header', 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'),
  tracePart('<= Recv data', 'fresh retry proof'),
].join('\n');
const retryReceipt = await persistCapturedTrace({ deliverablesDir: loopDir, findingId: 'INJ-12', trace: retryTrace, exitCode: 0 });
const plan = { steps: [{ method: 'GET', url: '${BASE_URL}/retry', expect: { status: 200, body_contains: 'fresh retry proof' } }] };
const retryEntry = { ...strictEntry('INJ-12', retryReceipt), title: 'RETRY_SUCCESS', http_replay: null };
const unrelated = { ...strictEntry('INJ-07', retryReceipt), title: 'UNRESOLVED_INITIAL', http_evidence_ids: [], http_evidence_receipts: [] };
const missing = { ...unrelated, vulnerability_id: 'INJ-09', title: 'MISSING_VERDICT' };
const expansionFailure = { ...unrelated, vulnerability_id: 'INJ-18', title: 'UNRESOLVED_EXPANSION' };
await writeLoop('injection_renumber_map.json', map('injection', { 'INJ-12': 'INJ-07', 'INJ-07': 'INJ-06', 'INJ-09': 'INJ-08' }));
await writeLoop('injection_exploit_collector.json', [retryEntry, unrelated, missing]);
await writeLoop('injection_exploit_collector_renumbered.json', [
  { ...retryEntry, vulnerability_id: 'INJ-07' }, { ...unrelated, vulnerability_id: 'INJ-06' }, { ...missing, vulnerability_id: 'INJ-08' },
]);
await writeLoop('explore_candidates_injection.json', { vulnerabilities: [{ ID: 'INJ-18' }] });
await writeLoop('explore_expansion_injection_exploit_collector.json', [expansionFailure]);
const failedVerdict = (id, stage = 'record') => ({
  ...strictVerdict(id, retryReceipt), status: 'failed', capture_ids: [], http_evidence_receipts: [], stage,
  reason: 'Fixture assertion failed', attempts: 3, failure_kind: 'retry_exhausted',
  replay_history: [1, 2, 3].map((attempt) => ({
    attempt, stage, error: `Failure ${attempt}`, capture_ids: [], variable_diagnostics: [], record_log_path: `/logs/${stage}.log`,
  })),
});
const retryVerdict = {
  ...strictVerdict('INJ-12', retryReceipt), stage: 'record-retry', attempts: 4,
  replay_history: [
    ...failedVerdict('INJ-12').replay_history,
    { attempt: 1, stage: 'record-retry', error: null, capture_ids: [retryReceipt.capture_id], variable_diagnostics: [], record_log_path: '/logs/record-retry.log' },
  ],
};
assert.deepEqual(await applyRecordRetryEvidence(loopDir, [retryVerdict], new Map([['INJ-12', plan]])), ['INJ-07']);
const updatedSource = await readLoop('injection_exploit_collector.json');
const updatedReport = await readLoop('injection_exploit_collector_renumbered.json');
assert.deepEqual(updatedSource[0].http_replay, plan);
assert.deepEqual(updatedReport[0].http_replay, plan);
assert.deepEqual(updatedSource[1], unrelated, 'retry must not overwrite an unrelated original ID matching the report ID');
assert.deepEqual(updatedReport[1], { ...unrelated, vulnerability_id: 'INJ-06' });
assert.deepEqual(updatedSource[2], missing);
console.log('PASS retry updates original and report namespaces separately without overwriting another finding');

await writeLoop('record_verification.json', [retryVerdict, failedVerdict('INJ-07'), failedVerdict('INJ-18', 'record-expansion')]);
// Packet admission intentionally reads the durable collector and mapping, just as production does.
await run('git', ['add', '--', '.'], { cwd: loopDir, env });
await run('git', ['commit', '-m', 'Retry and failed finding fixtures'], { cwd: loopDir, env });
const exclusions = await finalizeRecordReportAdmission(loopDir);
assert.deepEqual(exclusions.map((item) => [item.finding_id, item.report_finding_id]), [
  ['INJ-07', 'INJ-06'], ['INJ-09', 'INJ-08'], ['INJ-18', 'INJ-18'],
]);
assert.deepEqual(await readLoop('record_verified_finding_ids.json'), ['INJ-07']);
assert.deepEqual([...(await loadRecordReportFindingIds(loopDir))], ['INJ-07']);
assert.deepEqual(await validateRecordReportAdmission(loopDir), [], 'audited exclusions must not block verified findings');
assert.deepEqual(await readLoop('injection_exploit_collector.json'), updatedSource, 'unresolved findings retain their original records');
assert.deepEqual(await readLoop('explore_expansion_injection_exploit_collector.json'), [expansionFailure]);
const recorded = await readFile(path.join(loopDir, 'injection_recorded_exploitation_evidence.md'), 'utf8');
assert.match(recorded, /RETRY_SUCCESS/);
assert.doesNotMatch(recorded, /UNRESOLVED_INITIAL|MISSING_VERDICT/);
assert.doesNotMatch(await readFile(path.join(loopDir, 'explore_expansion_injection.md'), 'utf8'), /UNRESOLVED_EXPANSION/);
const failures = await aggregateRecordFailures(loopDir, new Map([
  ['injection', '/logs/injection-exploit.log'], ['injection-expansion', '/logs/injection-exploit-expansion.log'],
]));
assert.equal(failures.find((item) => item.finding_id === 'INJ-07').exploit_log_path, '/logs/injection-exploit.log');
assert.equal(failures.find((item) => item.finding_id === 'INJ-18').exploit_log_path, '/logs/injection-exploit-expansion.log');
assert.equal(failures[0].record_attempts.length, 3);
assert.deepEqual(failures[0].record_attempts.map((attempt) => attempt.error), ['Failure 1', 'Failure 2', 'Failure 3']);
await writeFinalRecordFailureAudit(loopDir, 'offline-fixture', failures, []);
const audit = (await readFile(path.join(loopDir, 'record-verification-failures.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
assert.ok(audit.every((item) => item.report_excluded === true && item.report_blocked === false && item.attempts === 3));
console.log('PASS exhausted and missing verdicts are explicitly excluded while source records, logs and diagnostics survive');

await run('git', ['add', '--', '.'], { cwd: loopDir, env });
await run('git', ['commit', '-m', 'Finalize audited report exclusions'], { cwd: loopDir, env });
const assembled = await assembleFinalReportWithEvidence(temporary, 'closed-loop', { info() {}, warn() {}, error() {} }, {
  exploit: true, participatingClasses: ['injection'],
});
assert.deepEqual(assembled.failedClasses, []);
assert.match(assembled.content, /RETRY_SUCCESS/);
assert.doesNotMatch(assembled.content, /UNRESOLVED_INITIAL|UNRESOLVED_EXPANSION|MISSING_VERDICT/);
// Losing proof after finalization must still be an error for a previously admitted finding.
await writeLoop('record_verification.json', [failedVerdict('INJ-07')]);
assert.deepEqual([...(await loadRecordReportFindingIds(loopDir))], []);
assert.ok((await validateRecordReportAdmission(loopDir)).includes('INJ-07: missing verified Record verdict'));
console.log('PASS committed report assembly includes verified findings only and rechecks proof after finalization');
