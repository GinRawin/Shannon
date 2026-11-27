/**
 * Offline regression for the DOM-marker XSS receipt and browser-only trust path.
 *
 * Run: node scripts/test-xss-dom-receipt.mjs
 *
 * The browser leg itself needs a real Chromium, so this covers the parts that decide whether a
 * persisted receipt is trustworthy: plan validation for the new assert_text action and the
 * hasTrustedBrowserReplay revalidation of a host-written dom_marker receipt.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp('/tmp/shannon-dom-receipt-');
await run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'apps/worker/tsconfig.json', '--outDir', `${temporary}/dist`, '--incremental', 'false'], { cwd: root });
await symlink(`${root}/apps/worker/node_modules`, `${temporary}/node_modules`);
const load = (name) => import(pathToFileURL(`${temporary}/dist/${name}.js`));
const { browserReplayPlanDigest, browserReplayPlanError, hasTrustedBrowserReplay } = await load('services/browser-replay');

const digest = (value) => createHash('sha256').update(value).digest('hex');
const dir = `${temporary}/deliverables`;
const findingId = 'XSS-12';
const attemptId = '11111111-2222-3333-4444-555555555555';
const secondAttemptId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const marker = `shannon_xss_${'a'.repeat(48)}`;
const origin = 'https://target.invalid';
const plan = {
  steps: [
    { action: 'goto', url: '${BASE_URL}/page?q=%3Cimg%20src%3Dx%20onerror%3Dalert(%22${XSS_MARKER}%22)%3E' },
    { action: 'assert_text', selector: 'body', value: '${XSS_MARKER}' },
  ],
};

let passed = 0;
const ok = (label, condition, detail) => {
  assert.ok(condition, detail ? `${label}: ${detail}` : label);
  passed += 1;
  console.log(`  ok  ${label}`);
};

ok('plan: an assert_text DOM plan is valid', browserReplayPlanError(plan) === undefined, browserReplayPlanError(plan));

/**
 * Materialize one host receipt directory plus the matching proof object. The attempt id must match
 * the directory the host would have written, so each receipt gets an explicit full 36-char id.
 */
async function writeReceipt(receiptAttemptId, overrides) {
  const relative = `browser-replay-verifications/${findingId}/${receiptAttemptId}`;
  await mkdir(`${dir}/${relative}`, { recursive: true });
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.from(`body${receiptAttemptId}`)]);
  await writeFile(`${dir}/${relative}/screenshot.png`, png);
  const receipt = {
    verifier: 'playwright-host-v1',
    finding_id: findingId,
    stage: 'record',
    attempt_id: receiptAttemptId,
    attempt: 1,
    plan_sha256: browserReplayPlanDigest(plan),
    http_capture_ids: [],
    verified_at: new Date().toISOString(),
    observed_at: new Date().toISOString(),
    target_origin: origin,
    page_url: `${origin}/page`,
    assertion_type: 'dom_marker',
    expected: marker,
    observed: marker,
    evidence_files: [`${relative}/screenshot.png`],
    evidence_sha256: [digest(png)],
    ...overrides,
  };
  const contents = `${JSON.stringify(receipt, null, 2)}\n`;
  await writeFile(`${dir}/${relative}/receipt.json`, contents);
  return { ...receipt, receipt_file: `${relative}/receipt.json`, receipt_sha256: digest(contents) };
}

const domProof = await writeReceipt(attemptId, {});
const dialogProof = await writeReceipt(secondAttemptId, { assertion_type: 'dialog_exact', http_capture_ids: ['capture-1'] });
const trust = (overrides) =>
  hasTrustedBrowserReplay({
    deliverablesDir: dir,
    findingId,
    plan,
    stage: 'record',
    targetUrl: origin,
    httpCaptureIds: [],
    ...overrides,
  });

ok('dom: a host-written dom_marker receipt with no captures is trusted', (await trust({ verification: domProof })) === true);
ok('dom: a tampered observed value is rejected', (await trust({ verification: { ...domProof, observed: 'forged' } })) === false);
ok(
  'dom: claiming an HTTP capture the caller does not have is rejected',
  (await trust({ verification: { ...domProof, http_capture_ids: ['capture-1'] } })) === false,
);
ok('dom: citing a capture the receipt did not observe is rejected', (await trust({ httpCaptureIds: ['capture-1'] })) === false);
ok(
  'dom: a legacy assertion type is rejected',
  (await trust({ verification: { ...domProof, assertion_type: 'dom_text_contains' } })) === false,
);
ok(
  'dom: a plan that no longer matches the receipt digest is rejected',
  (await trust({ verification: domProof, plan: { steps: [plan.steps[0]] } })) === false,
);
ok(
  'dialog: a receipt citing its complete HTTP capture set is still trusted',
  (await trust({ verification: dialogProof, httpCaptureIds: ['capture-1'] })) === true,
);
ok(
  'dialog: a receipt whose captures do not match the caller is rejected',
  (await trust({ verification: dialogProof, httpCaptureIds: [] })) === false,
);
ok(
  'dialog: a receipt is rejected when its on-disk bytes disagree with the proof',
  (await trust({ verification: { ...dialogProof, page_url: `${origin}/other` } })) === false,
);

console.log(`\nall ${passed} checks passed`);
