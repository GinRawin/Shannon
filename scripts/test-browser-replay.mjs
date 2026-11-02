// Local-only regression for host-observed XSS proof, retry provenance and report admission.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp('/tmp/shannon-browser-replay-');
await run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'apps/worker/tsconfig.json', '--outDir', `${temporary}/dist`, '--incremental', 'false'], { cwd: root });
await symlink(`${root}/apps/worker/node_modules`, `${temporary}/node_modules`);
const load = (name) => import(pathToFileURL(`${temporary}/dist/${name}.js`));
const { browserReplayPlanError, verifyBrowserReplay, hasTrustedBrowserReplay } = await load('services/browser-replay');
const { verifyHttpReplay } = await load('services/http-replay');
const { createRecordCollector } = await load('collectors/record-collector');
const { createExploitCollector } = await load('collectors/exploit-collector');
const { createExploitReviewCollector } = await load('collectors/exploit-review-collector');
const { applyRecordRetryEvidence, validateRecordReportAdmission, loadRecordReportFindingIds } = await load('services/record-verification');
const { attachHttpEvidence } = await load('services/http-evidence');
const { updateReplayVariables, loadReplayVariables } = await load('services/replay-variables');
const { getAgentGitPaths } = await load('services/agent-git-paths');
const { buildRenumberMap } = await load('services/renumber-core');
const { deepRemapStrings } = await load('services/compaction-core');

let cleaned = false;
const externalRequests = [];
const external = createServer((request, response) => { externalRequests.push(request.url); response.end('outside'); });
await new Promise((resolve) => external.listen(0, '127.0.0.1', resolve));
const outside = `http://127.0.0.1:${external.address().port}`;
const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://fixture.invalid');
  response.setHeader('Content-Type', 'text/html');
  const marker = JSON.stringify(url.searchParams.get('marker'));
  switch (url.pathname) {
    case '/reflect': response.end(`<h1>Vulnerable fixture</h1>${url.searchParams.get('payload')}`); break;
    case '/form': response.end('<input id="payload"><button id="trigger" onclick="document.querySelector(\'#sink\').innerHTML=document.querySelector(\'#payload\').value">Submit</button><div id="sink"></div>'); break;
    case '/text': response.end(`<script>document.body.textContent=${marker}</script>`); break;
    case '/title': response.end(`<script>document.title=${marker}</script>`); break;
    case '/wrong': response.end('<script>alert("wrong marker")</script>'); break;
    case '/auth': response.end(`<script>if(document.cookie.includes('session=good')&&localStorage.getItem('auth')==='good')alert(${marker})</script>`); break;
    case '/cleanup': cleaned = true; response.end('<div id="cleaned">Cleaned</div>'); break;
    case '/external': response.end(`<script>fetch(${JSON.stringify(outside)}).catch(()=>{});new WebSocket(${JSON.stringify(outside.replace('http:', 'ws:'))});alert(${marker})</script>`); break;
    case '/popup': response.end(`<script>window.open('/redirect');alert(${marker});setTimeout(()=>document.body.innerHTML='<div id=done>done</div>',250)</script>`); break;
    case '/redirect-chain': response.writeHead(302, { Location: '/redirect' }); response.end(); break;
    case '/redirect': response.writeHead(302, { Location: `${outside}/escape` }); response.end(); break;
    default: response.end('<h1>fixture proof</h1>');
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const target = `http://127.0.0.1:${server.address().port}`;
const dir = `${temporary}/deliverables`;
await mkdir(dir);
const markerPlaceholder = '${XSS_MARKER}';
const payload = encodeURIComponent(`<script>alert("${markerPlaceholder}")</script>`).replace(encodeURIComponent(markerPlaceholder), markerPlaceholder);
const plan = { steps: [{ action: 'goto', url: '${BASE_URL}/reflect?payload=' + payload }], timeout_ms: 10000 };
const httpPlan = { steps: [{ method: 'GET', url: '${BASE_URL}/', expect: { status: 200, body_contains: 'fixture proof' } }] };
const invoke = async (collector, name, input) => {
  const tool = collector.tools.find((tool) => tool.name === name);
  assert.ok(tool, `Missing tool ${name}`);
  return JSON.parse((await tool.execute('fixture', input)).content[0].text);
};
const verdict = (status, captures) => ({ finding_id: 'XSS-12', status, capture_ids: captures, reason: 'Fixture verification', frontend_status: 'not_found', frontend_url: null, frontend_trigger: null, frontend_reason: 'Fixture only' });
const env = { ...process.env, GIT_AUTHOR_NAME: 'Browser fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Browser fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' };
async function commit(files) {
  for (const [name, value] of Object.entries(files)) await writeFile(`${dir}/${name}`, JSON.stringify(value));
  await run('git', ['add', '--', ...Object.keys(files)], { cwd: dir, env });
  await run('git', ['commit', '-m', 'Browser fixture'], { cwd: dir, env });
}
const checks = [];
async function check(name, body) { await body(); checks.push(name); console.log(`PASS ${name}`); }
try {
  await check('browser plans reject evaluate, scripted selectors and missing challenge', async () => {
    assert.equal(browserReplayPlanError(plan), undefined);
    assert.ok(browserReplayPlanError({ steps: [{ action: 'evaluate', script: 'alert(1)' }] }));
    assert.ok(browserReplayPlanError({ steps: [{ action: 'goto', url: 'https://outside.invalid/${XSS_MARKER}' }] }));
    assert.ok(browserReplayPlanError({ steps: [plan.steps[0], { action: 'click', selector: '${SELECTOR}' }] }));
    assert.ok(browserReplayPlanError({ steps: [{ action: 'goto', url: '${BASE_URL}/' }] }));
    assert.equal(browserReplayPlanError({ steps: [plan.steps[0], { action: 'press', selector: 'body', key: 'Enter' }] }), undefined);
  });
  const http = await verifyHttpReplay({ findingId: 'XSS-12', plan: httpPlan, variables: {}, deliverablesDir: dir, targetUrl: target });
  assert.ok(http.verification, http.error);
  const args = { findingId: 'XSS-12', stage: 'record', attempt: 1, plan, variables: {}, httpEvidence: http.evidence, targetUrl: target, deliverablesDir: dir };
  const trust = (verification, overrides = {}) => hasTrustedBrowserReplay({ deliverablesDir: dir, findingId: 'XSS-12', stage: 'record', plan, verification, httpCaptureIds: http.evidence.map((item) => item.capture_id), targetUrl: target, ...overrides });
  let proof;
  await check('real reflected XSS yields a fresh host dialog receipt and screenshot', async () => {
    const result = await verifyBrowserReplay(args);
    assert.ok(result.verification, result.error); proof = result.verification;
    assert.equal(proof.observed, proof.expected);
    assert.match(proof.expected, /^shannon_xss_[a-f0-9]{48}$/);
    assert.equal(await trust(proof), true);
    const second = await verifyBrowserReplay(args);
    assert.ok(second.verification, second.error);
    assert.notEqual(second.verification.expected, proof.expected);
    assert.notEqual(second.verification.attempt_id, proof.attempt_id);
  });
  await check('UI fill and trigger execute the documented payload', async () => {
    const result = await verifyBrowserReplay({ ...args, plan: { steps: [
      { action: 'goto', url: '${BASE_URL}/form' },
      { action: 'fill', selector: '#payload', value: '<img src=x onerror=alert("${XSS_MARKER}")>' },
      { action: 'click', selector: '#trigger' },
    ] } });
    assert.ok(result.verification, result.error);
  });
  await check('text reflection, a title change and the wrong dialog cannot prove XSS', async () => {
    for (const endpoint of ['text', 'title', 'wrong']) {
      const result = await verifyBrowserReplay({ ...args, plan: { steps: [{ action: 'goto', url: '${BASE_URL}/' + endpoint + '?marker=${XSS_MARKER}' }], timeout_ms: 1000 } });
      assert.ok(result.error, endpoint); assert.equal(result.verification, undefined);
    }
  });
  await check('fresh authentication state is loaded only when requested', async () => {
    const authStatePath = `${temporary}/auth.json`;
    await writeFile(authStatePath, JSON.stringify({ cookies: [{ name: 'session', value: 'good', domain: '127.0.0.1', path: '/', expires: -1, httpOnly: false, secure: false, sameSite: 'Lax' }], origins: [{ origin: target, localStorage: [{ name: 'auth', value: 'good' }] }] }));
    const authPlan = { steps: [{ action: 'goto', url: '${BASE_URL}/auth?marker=${XSS_MARKER}' }], use_auth_state: true, timeout_ms: 1000 };
    assert.ok((await verifyBrowserReplay({ ...args, plan: authPlan })).error);
    const result = await verifyBrowserReplay({ ...args, plan: { ...authPlan, timeout_ms: 10000 }, authStatePath });
    assert.ok(result.verification, result.error);
  });
  await check('cross-origin navigation and HTTP/WebSocket requests stay blocked', async () => {
    const blocked = await verifyBrowserReplay({ ...args, plan: { steps: [{ action: 'goto', url: '${BASE_URL}@127.0.0.1:1/?marker=${XSS_MARKER}' }] } });
    assert.ok(blocked.error);
    assert.ok((await verifyBrowserReplay({ ...args, plan: { steps: [{ action: 'goto', url: '${BASE_URL}/redirect?marker=${XSS_MARKER}' }], timeout_ms: 1000 } })).error);
    const result = await verifyBrowserReplay({ ...args, plan: { steps: [{ action: 'goto', url: '${BASE_URL}/external?marker=${XSS_MARKER}' }] } });
    assert.ok(result.verification, result.error);
    const chain = await verifyBrowserReplay({ ...args, plan: { steps: [{ action: 'goto', url: '${BASE_URL}/redirect-chain?marker=${XSS_MARKER}' }], timeout_ms: 1000 } });
    assert.ok(chain.error);
    const popup = await verifyBrowserReplay({ ...args, plan: { steps: [{ action: 'goto', url: '${BASE_URL}/popup?marker=${XSS_MARKER}' }, { action: 'wait_for', selector: '#done' }] } });
    assert.ok(popup.verification, popup.error);
    assert.deepEqual(externalRequests, []);
  });
  await check('cleanup runs on success and failure, and failed cleanup rejects proof', async () => {
    const cleanup = [{ action: 'goto', url: '${BASE_URL}/cleanup' }];
    cleaned = false;
    assert.ok((await verifyBrowserReplay({ ...args, plan: { ...plan, cleanup } })).verification);
    assert.equal(cleaned, true);
    cleaned = false;
    const failure = { steps: [plan.steps[0], { action: 'click', selector: '#missing' }], cleanup, timeout_ms: 15000 };
    assert.ok((await verifyBrowserReplay({ ...args, plan: failure })).error);
    assert.equal(cleaned, true);
    const badCleanup = { ...plan, cleanup: [{ action: 'click', selector: '#missing' }], timeout_ms: 1000 };
    assert.ok((await verifyBrowserReplay({ ...args, plan: badCleanup })).error);
    const cancelled = new AbortController(); cancelled.abort();
    assert.ok((await verifyBrowserReplay({ ...args, signal: cancelled.signal })).error);
  });
  await check('receipt validation rejects legacy assertions, changed identities, plans, captures and file tampering', async () => {
    assert.equal(await trust({ assertion_type: 'dialog_text_contains', expected: 'x', observed: 'x', evidence_files: ['fake.png'] }), false);
    for (const change of [{ finding_id: 'XSS-99' }, { stage: 'record-retry' }, { expected: 'known' }, { target_origin: outside }]) assert.equal(await trust({ ...proof, ...change }), false);
    assert.equal(await trust(proof, { httpCaptureIds: ['unrelated'] }), false);
    assert.equal(await trust(proof, { plan: { ...plan, timeout_ms: 20000 } }), false);
    const file = `${dir}/${proof.evidence_files[0]}`;
    const bytes = await readFile(file); await writeFile(file, 'forged');
    assert.equal(await trust(proof), false); await writeFile(file, bytes);
    const receipt = `${dir}/${proof.receipt_file}`;
    const contents = await readFile(receipt); await writeFile(receipt, '{}');
    assert.equal(await trust(proof), false); await writeFile(receipt, contents);
    const escaped = `${temporary}/escaped.png`; await writeFile(escaped, bytes); await rm(file); await symlink(escaped, file);
    assert.equal(await trust(proof), false); await rm(file); await writeFile(file, bytes);
    assert.equal(await trust(proof), true);
  });
  const options = {
    deliverablesDir: dir, sourceDir: temporary, targetUrl: target, validIds: new Set(['XSS-12']), xssFindingIds: new Set(['XSS-12']),
    verificationPlans: new Map([['XSS-12', httpPlan]]), browserPlans: new Map([['XSS-12', plan]]), stage: 'record-retry',
    verifyReplay: (findingId, saved) => verifyHttpReplay({ findingId, plan: saved, variables: {}, deliverablesDir: dir, targetUrl: target }),
    verifyBrowserReplay: (findingId, saved, httpEvidence, attempt, signal) => verifyBrowserReplay({ ...args, findingId, plan: saved, httpEvidence, attempt, signal, stage: 'record-retry' }),
  };
  let recorded;
  await check('Record executes both plans, rejects fabricated browser assertions and bounds failed attempts', async () => {
    const failed = createRecordCollector({ ...options, verifyBrowserReplay: async () => ({ verification: { ...proof, observed: 'forged' } }) });
    assert.equal(failed.tools.some((tool) => tool.name === 'verify_browser_assertion'), false);
    for (let i = 0; i < 3; i++) assert.equal((await invoke(failed, 'verify_http_replay', { finding_id: 'XSS-12' })).status, 'error');
    assert.match((await invoke(failed, 'verify_http_replay', { finding_id: 'XSS-12' })).message, /three-attempt/);
    assert.equal((await invoke(failed, 'record_verification', verdict('verified', []))).status, 'error');
    assert.equal(failed.getAll()[0].attempts, 3);
    assert.equal(failed.getAll()[0].replay_history.length, 3);
    const collector = createRecordCollector(options);
    const result = await invoke(collector, 'verify_http_replay', { finding_id: 'XSS-12' });
    assert.equal(result.status, 'success', result.message);
    assert.ok(result.browser_verification);
    assert.equal((await invoke(collector, 'record_verification', verdict('verified', result.captures.map((item) => item.capture_id)))).status, 'verified');
    recorded = collector.getAll()[0];
  });
  await check('retry proof survives renumbering and report admission, while legacy and tampered proof fail', async () => {
    const entry = { status: 'exploited', vulnerability_id: 'XSS-12', title: 'Fixture', severity: 'high', overview: 'Fixture', proof_of_impact: 'Dialog executed', verification_method: 'mixed', http_evidence_display: 'include', http_replay: httpPlan, browser_replay: plan };
    await run('git', ['init'], { cwd: dir });
    await commit({
      'xss_exploit_collector.json': [entry],
      'xss_exploit_collector_renumbered.json': [{ ...entry, vulnerability_id: 'XSS-01' }],
      'xss_renumber_map.json': { map: { 'XSS-12': 'XSS-01' } },
    });
    assert.deepEqual(await applyRecordRetryEvidence(dir, [recorded], new Map([['XSS-12', httpPlan]]), new Map([['XSS-12', plan]])), ['XSS-01']);
    await commit(Object.fromEntries(await Promise.all(['xss_exploit_collector.json', 'xss_exploit_collector_renumbered.json'].map(async (name) => [name, JSON.parse(await readFile(`${dir}/${name}`, 'utf8'))]))));
    await writeFile(`${dir}/record_verification.json`, JSON.stringify([recorded]));
    assert.deepEqual(await validateRecordReportAdmission(dir), []);
    assert.deepEqual([...await loadRecordReportFindingIds(dir)], ['XSS-01']);
    const findings = [{ finding_id: 'XSS-01', additional_sections: [] }];
    const attached = await attachHttpEvidence(findings, dir);
    assert.ok(attached[0].additional_sections.some((section) => section.heading === '浏览器验证证据'));
    const renumbered = buildRenumberMap([{ ...entry, browser_verification: recorded.browser_verification }], 'xss');
    assert.deepEqual(renumbered.renumbered[0].browser_replay, plan);
    assert.deepEqual(deepRemapStrings({ browser_replay: plan, browser_verification: recorded.browser_verification }, new Map([['XSS-12', 'XSS-01']])), { browser_replay: plan, browser_verification: recorded.browser_verification });
    await writeFile(`${dir}/record_verification.json`, JSON.stringify([{ ...recorded, browser_verification: { expected: 'fake', observed: 'fake' } }]));
    assert.deepEqual(await validateRecordReportAdmission(dir), ['XSS-01: missing JavaScript execution evidence']);
    await writeFile(`${dir}/record_verification.json`, JSON.stringify([recorded]));
    await writeFile(`${dir}/${recorded.browser_verification.receipt_file}`, '{}');
    assert.deepEqual([...await loadRecordReportFindingIds(dir)], []);
    await assert.rejects(attachHttpEvidence(findings, dir), /trusted browser/);
  });
  await check('browser-only input variables can be corrected privately; host markers remain protected', async () => {
    const privateDir = `${temporary}/variables`;
    const browser = { ...plan, steps: [plan.steps[0], { action: 'fill', selector: '#input', value: '${INPUT}' }] };
    assert.deepEqual(await updateReplayVariables(privateDir, 'XSS-12', httpPlan, { INPUT: 'observed' }, [], {}, browser), ['INPUT']);
    assert.equal((await loadReplayVariables(privateDir, 'XSS-12')).INPUT, 'observed');
    await assert.rejects(updateReplayVariables(privateDir, 'XSS-12', httpPlan, { XSS_MARKER: 'forged' }, [], {}, browser));
  });
  await check('Exploit and review require host-executable XSS plans and Record checkpoints browser artifacts', async () => {
    const exploit = { status: 'exploited', vulnerability_id: 'XSS-12', title: 'Fixture', vulnerable_location: '/', overview: 'Fixture', severity: 'high', severity_rationale: 'Fixture', impact: 'JS execution', exploitation_steps: ['Trigger'], proof_of_impact: 'Dialog', verification_method: 'mixed', http_evidence_display: 'include', http_evidence_reason: 'Fixture', http_replay: httpPlan };
    const collector = createExploitCollector({ vulnClass: 'xss', validIds: new Set(['XSS-12']) });
    assert.equal((await invoke(collector, 'add_exploit', exploit)).status, 'error');
    assert.equal((await invoke(collector, 'add_exploit', { ...exploit, browser_replay: plan })).status, 'success');
    const review = createExploitReviewCollector(new Set(['XSS-12']));
    const decision = { finding_id: 'XSS-12', verdict: 'retry', reason: 'Retry', revised_http_replay: httpPlan, variable_requirements: {}, record_instructions: ['Replay both saved plans'], expected_evidence: { http: 'complete packet', browser: 'host challenge dialog' } };
    assert.equal((await invoke(review, 'submit_exploit_review', decision)).status, 'error');
    assert.equal((await invoke(review, 'submit_exploit_review', { ...decision, revised_browser_replay: plan })).status, 'success');
    assert.ok(getAgentGitPaths('record').some((file) => file.endsWith('browser-replay-verifications')));
  });
  console.log(`Validated ${checks.length} browser replay regressions.`);
} finally {
  server.closeAllConnections(); external.closeAllConnections();
  await Promise.all([new Promise((resolve) => server.close(resolve)), new Promise((resolve) => external.close(resolve))]);
}
