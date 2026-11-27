/**
 * Offline regression for a pure client-side XSS sink: a URL-fragment/DOM-only payload that never
 * reaches the server has no HTTP impact to assert, so it is admitted to the report by its host
 * browser receipt alone. This covers receipt detection, report admission, evidence attachment and
 * the Record collector's browser-only verification gate.
 *
 * Run: node scripts/test-xss-browser-only-admission.mjs
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp('/tmp/shannon-browser-only-');
await run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'apps/worker/tsconfig.json', '--outDir', `${temporary}/dist`, '--incremental', 'false'], { cwd: root });
await symlink(`${root}/apps/worker/node_modules`, `${temporary}/node_modules`);
const load = (name) => import(pathToFileURL(`${temporary}/dist/${name}.js`));
const { browserReplayPlanDigest } = await load('services/browser-replay');
const { attachHttpEvidence, loadBrowserBackedFindingIds, loadPacketBackedFindingIds } = await load('services/http-evidence');
const { finalizeRecordReportAdmission, loadRecordReportFindingIds, validateRecordReportAdmission } = await load('services/record-verification');
const { createRecordCollector } = await load('collectors/record-collector');

const digest = (value) => createHash('sha256').update(value).digest('hex');
const dir = `${temporary}/deliverables`;
await mkdir(dir);
const env = {
  ...process.env, GIT_AUTHOR_NAME: 'Browser-only test', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
  GIT_COMMITTER_NAME: 'Browser-only test', GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
};
async function commit(files) {
  for (const [name, value] of Object.entries(files)) {
    await writeFile(path.join(dir, name), `${JSON.stringify(value, null, 2)}\n`);
  }
  await run('git', ['add', '--', ...Object.keys(files)], { cwd: dir, env });
  await run('git', ['commit', '-m', 'Browser-only fixture'], { cwd: dir, env });
}
await run('git', ['init'], { cwd: dir });

const origin = 'https://target.invalid';
const marker = `shannon_xss_${'a'.repeat(48)}`;
const taskId = 'XSS-01';
const reportId = 'XSS-05';
const attemptId = '11111111-2222-3333-4444-555555555555';
// The payload lives in the URL fragment, so the server never sees it and returns nothing to assert on.
const plan = {
  steps: [
    { action: 'goto', url: '${BASE_URL}/page#%3Cimg%20src%3Dx%20onerror%3Dalert(%22${XSS_MARKER}%22)%3E' },
    { action: 'assert_text', selector: 'body', value: '${XSS_MARKER}' },
  ],
};
async function writeBrowserReceipt(observed = marker) {
  const relative = `browser-replay-verifications/${taskId}/${attemptId}`;
  await mkdir(`${dir}/${relative}`, { recursive: true });
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.from('body')]);
  await writeFile(`${dir}/${relative}/screenshot.png`, png);
  const receipt = {
    verifier: 'playwright-host-v1', finding_id: taskId, stage: 'record', attempt_id: attemptId, attempt: 1,
    plan_sha256: browserReplayPlanDigest(plan), http_capture_ids: [],
    verified_at: new Date().toISOString(), observed_at: new Date().toISOString(),
    target_origin: origin, page_url: `${origin}/page`,
    assertion_type: 'dom_marker', expected: marker, observed,
    evidence_files: [`${relative}/screenshot.png`], evidence_sha256: [digest(png)],
  };
  const contents = `${JSON.stringify(receipt, null, 2)}\n`;
  await writeFile(`${dir}/${relative}/receipt.json`, contents);
  return { ...receipt, receipt_file: `${relative}/receipt.json`, receipt_sha256: digest(contents) };
}
const proof = await writeBrowserReceipt();
const entry = {
  status: 'exploited', vulnerability_id: taskId, title: 'DOM XSS', severity: 'high',
  overview: 'Fixture', impact: 'Fixture', remediation: 'Fixture', auth_state: 'None', prerequisites: 'None',
  vulnerable_location: '/page#fragment', owasp_category: 'A03:2025',
  exploitation_steps: [{ items: [{ kind: 'prose', text: 'Fixture' }] }],
  browser_replay: plan, http_evidence_display: 'omit', verification_method: 'browser',
  browser_verification: proof, browser_evidence_files: proof.evidence_files,
};
await commit({
  'xss_renumber_map.json': { vulnerability_type: 'xss', map: { [taskId]: reportId }, order: [taskId], excluded: [] },
  'xss_exploit_collector.json': [entry],
  'xss_exploit_collector_renumbered.json': [{ ...entry, vulnerability_id: reportId }],
  'record_verification.json': [{
    finding_id: taskId, status: 'verified', reason: 'browser-only DOM XSS', capture_ids: [],
    frontend_status: 'unable_to_determine', frontend_url: null, frontend_trigger: null, frontend_reason: 'hash sink',
    browser_verification: proof, stage: 'record',
  }],
});

let passed = 0;
const ok = (label, condition) => {
  assert.ok(condition, label);
  passed += 1;
  console.log(`  ok  ${label}`);
};

const browserBacked = await loadBrowserBackedFindingIds(dir);
ok('a trusted no-packet XSS receipt is browser-backed', [...browserBacked].join() === reportId);
ok('a browser-only finding is not packet-backed', (await loadPacketBackedFindingIds(dir)).size === 0);
ok('report admission accepts the browser-only finding', (await validateRecordReportAdmission(dir)).length === 0);
ok('finalization excludes nothing', (await finalizeRecordReportAdmission(dir)).length === 0);
ok('the report allowlist carries the browser-only finding', [...(await loadRecordReportFindingIds(dir))].join() === reportId);

const projected = await attachHttpEvidence([{ finding_id: reportId, title: 'DOM XSS', additional_sections: [] }], dir, []);
ok('evidence attachment admits the browser-only finding', projected.length === 1);
ok('its verification method is browser', projected[0].verification_method === 'browser');
ok('it displays no captured HTTP section', projected[0].http_evidence_display === 'omit');
const coverage = projected[0].additional_sections.find((section) => section.heading === '自动化重放覆盖');
ok('coverage prose states the client-side-only proof', coverage.items[0].text.includes('纯客户端'));

// --- Collector: a browser-only XSS verifies and can be marked verified ----------------------
const collectorFor = (options) =>
  createRecordCollector({ deliverablesDir: dir, targetUrl: origin, sourceDir: dir, stage: 'record', ...options });
const tool = (collector, name) => collector.tools.find((item) => item.name === name);
const parse = (result) => JSON.parse(result.content[0].text);

const xssCollector = collectorFor({
  validIds: new Set([taskId]), xssFindingIds: new Set([taskId]), browserPlans: new Map([[taskId, plan]]),
  verifyReplay: async () => ({ error: 'An HTTP replay must not run for a browser-only sink.' }),
  verifyBrowserReplay: async () => ({ verification: proof }),
});
const verified = await tool(xssCollector, 'verify_http_replay').execute('1', { finding_id: taskId });
ok('browser-only XSS verification succeeds without an HTTP plan', parse(verified).status === 'success');
const verdict = await tool(xssCollector, 'record_verification').execute('2', {
  finding_id: taskId, status: 'verified', reason: 'browser-only DOM XSS', capture_ids: [],
  frontend_status: 'unable_to_determine', frontend_url: null, frontend_trigger: null, frontend_reason: 'hash sink',
});
ok('a browser-only XSS verdict is accepted', parse(verdict).recorded === taskId && parse(verdict).status === 'verified');

const noBrowserCollector = collectorFor({
  validIds: new Set([taskId]), xssFindingIds: new Set([taskId]), browserPlans: new Map(),
  verifyReplay: async () => ({ error: 'unused' }),
});
const withoutPlan = await tool(noBrowserCollector, 'verify_http_replay').execute('1', { finding_id: taskId });
ok('an XSS without any plan is refused', /No structured HTTP verification plan/.test(parse(withoutPlan).message));

const nonXssCollector = collectorFor({ validIds: new Set(['AUTH-09']), verifyReplay: async () => ({ error: 'unused' }) });
const nonXss = await tool(nonXssCollector, 'verify_http_replay').execute('1', { finding_id: 'AUTH-09' });
ok('a non-XSS finding still requires an HTTP plan', /No structured HTTP verification plan/.test(parse(nonXss).message));

const captureCiteCollector = collectorFor({
  validIds: new Set([taskId]), xssFindingIds: new Set([taskId]), browserPlans: new Map([[taskId, plan]]),
  verifyReplay: async () => ({ error: 'unused' }),
  verifyBrowserReplay: async () => ({ verification: proof }),
});
await tool(captureCiteCollector, 'verify_http_replay').execute('1', { finding_id: taskId });
const badVerdict = await tool(captureCiteCollector, 'record_verification').execute('2', {
  finding_id: taskId, status: 'verified', reason: 'x', capture_ids: ['capture-1'],
  frontend_status: 'unable_to_determine', frontend_url: null, frontend_trigger: null, frontend_reason: 'x',
});
ok('a browser-only verdict may not cite HTTP captures', parse(badVerdict).status === 'error');

// --- Tampering: a receipt whose observed value disagrees with the challenge fails closed ------
await writeBrowserReceipt('forged');
ok('a tampered receipt stops being browser-backed', (await loadBrowserBackedFindingIds(dir)).size === 0);
ok(
  'a tampered receipt fails report admission',
  (await validateRecordReportAdmission(dir)).some((reason) => /missing complete associated HTTP packet/.test(reason)),
);

console.log(`\nall ${passed} checks passed`);
