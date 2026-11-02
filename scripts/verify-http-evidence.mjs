// Focused integration regression checks. All HTTP requests go to a temporary loopback server.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, readdir, writeFile, symlink, stat, unlink, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp('/tmp/shannon-http-check-');
function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd ?? root, env: { ...process.env, ...options.env }, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = [];
    child.stdout.on('data', (data) => stdout.push(data));
    child.stderr.on('data', (data) => stderr.push(data));
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }));
  });
}
const build = await run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'apps/worker/tsconfig.json', '--outDir', `${temporary}/dist`, '--incremental', 'false']);
assert.equal(build.code, 0, build.stdout + build.stderr);
await symlink(`${root}/apps/worker/node_modules`, `${temporary}/node_modules`);
const load = (name) => import(pathToFileURL(`${temporary}/dist/${name}.js`));
const { parseCurlTrace } = await load('services/http-capture');
const { captureHttpRequest, readVerifiedHttpEvidence } = await load('services/capture-http-request');
const { verifyHttpReplay, replayPlanDigest, hasVerifiedReplay, containsReplaySecret, replayPlanError } = await load('services/http-replay');
const { attachHttpEvidence, configuredCaptureRedactions, renderCapturedHttpEvidence, writeReproductionScript } = await load('services/http-evidence');
const { buildRenumberMap } = await load('services/renumber-core');
const { deepRemapStrings } = await load('services/compaction-core');
const { createExploitCollector } = await load('collectors/exploit-collector');
const { createRecordCollector } = await load('collectors/record-collector');
const { loadReplayVariables, updateReplayVariables } = await load('services/replay-variables');
const { buildAddFindingSchema, createFindingCollector } = await load('collectors/finding-collector');
const { renderReport } = await load('services/report-renderer');
const { adaptReportToTypst } = await load('services/report-json-adapter');
const { surfaceReportOutputs } = await load('services/report-output-surface');
const { finalizeReport } = await load('services/report-finalization');
const { snapshotCurlInvocation } = await load('services/curl-invocation');
const { describeArgumentInput, describeFileInput, describeVerificationInputs } = await load('services/reproduction-inputs');

const results = [];
async function check(name, body) {
  await body(); results.push(name); console.log(`PASS ${name}`);
}
const received = [];
let created = false;
const binary = Buffer.from([0, 255, 254, 97]);
const password = 'fixture-password-"quoted"';
const server = createServer(async (request, response) => {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  received.push({ url: request.url, method: request.method, body, headers: request.headers });
  if (request.url === '/slow') { setTimeout(() => response.end('late response'), 1500); }
  else if (request.url === '/hex') response.end('ab');
  else if (request.url === '/large') response.end(Buffer.alloc(70000, 'Z'));
  else if (request.url === '/binary') response.end(binary);
  else if (request.url === '/redirect') { response.writeHead(302, { Location: '/hex' }); response.end('redirect'); }
  else if (request.url === '/login') {
    const credentials = JSON.parse(body.toString());
    if (credentials.password !== password) { response.writeHead(401); response.end('Denied'); }
    else { response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ data: { token: 'good' } })); }
  } else if (request.url === '/cookie') { response.setHeader('Set-Cookie', 'session=good'); response.end('session issued'); }
  else if (request.url === '/create') { created = true; response.end('created fixture record'); }
  else if (request.url === '/created' && request.method === 'DELETE') { created = false; response.writeHead(204); response.end(); }
  else if (request.url === '/cleanup-fail') { response.writeHead(500); response.end('cleanup failed'); }
  else if (request.url === '/protected' && (request.headers.authorization === 'Bearer good' || request.headers.cookie === 'session=good')) {
    response.end('private-audit-record INJ-02');
  } else { response.writeHead(401); response.end('Denied'); }
});

try {
  await check('report writer schema and prompt no longer request a narrative evidence field', async () => {
    for (const exploit of [true, false]) {
      const schema = buildAddFindingSchema(exploit);
      assert.ok(!Object.hasOwn(schema.properties, 'proof_of_impact'));
      assert.ok(!schema.required.includes('proof_of_impact'));
    }
    const prompt = await readFile(`${root}/apps/worker/prompts/report-executive.txt`, 'utf8');
    assert.doesNotMatch(prompt, /proof_of_impact|proof of impact/i);
    const collector = createFindingCollector(true);
    const result = await collector.tools[0].execute('fixture', {
      finding_id: 'INJ-01', title: 'Fixture', category: 'Injection', severity: 'high',
      owasp_category: 'A05:2025 — Injection', auth_state: 'Fixture', prerequisites: 'None',
      exploitation_steps: [{ items: [{ kind: 'prose', text: 'Preserved step' }] }],
      vulnerable_location: '/fixture', overview: 'Fixture', impact: 'Fixture', remediation: 'Fixture',
    });
    assert.equal(JSON.parse(result.content[0].text).status, 'success');
    assert.ok(!Object.hasOwn(collector.getAll()[0], 'proof_of_impact'));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const target = `http://127.0.0.1:${server.address().port}`;
  const dir = `${temporary}/deliverables`;
  await mkdir(dir);
  const noProxy = { HTTP_PROXY: '', HTTPS_PROXY: '', ALL_PROXY: '', http_proxy: '', https_proxy: '', all_proxy: '', NO_PROXY: '*', no_proxy: '*' };
  Object.assign(process.env, noProxy);
  const wrapper = `${temporary}/dist/scripts/shannon-curl.js`;
  async function capture(id, args) {
    const execution = await run(process.execPath, [wrapper, '--finding-id', id, '--', ...args], { env: { SHANNON_DELIVERABLES_DIR: dir, ...noProxy } });
    assert.equal(execution.code, 0, execution.stderr);
    const files = (await readdir(`${dir}/http-exchanges/${id}`)).filter((file) => file.endsWith('.json')).sort();
    return JSON.parse(await readFile(`${dir}/http-exchanges/${id}/${files.at(-1)}`, 'utf8'));
  }
  let originalCapture;
  await check('actual GET headers, hex-looking body, and original trace survive decoding', async () => {
    const captureData = await capture('INJ-01', ['-sS', `${target}/hex`]);
    assert.deepEqual(captureData.errors, []);
    assert.match(captureData.exchanges[0].request, /^GET \/hex HTTP\/1.1\r\nHost:/);
    const raw = Buffer.from(captureData.exchanges[0].response_base64, 'base64');
    assert.equal(raw.subarray(raw.indexOf('\r\n\r\n') + 4).toString(), 'ab');
    assert.match(captureData.trace, /61 62/);
  });
  await check('large and binary responses preserve every byte', async () => {
    const large = await capture('INJ-03', ['-sS', `${target}/large`]);
    assert.deepEqual(large.errors, []);
    const data = Buffer.from(large.exchanges[0].response_base64, 'base64');
    assert.deepEqual(data.subarray(data.indexOf('\r\n\r\n') + 4), Buffer.alloc(70000, 'Z'));
    const capturedBinary = await capture('INJ-04', ['-sS', `${target}/binary`]);
    const raw = Buffer.from(capturedBinary.exchanges[0].response_base64, 'base64');
    assert.deepEqual(raw.subarray(raw.indexOf('\r\n\r\n') + 4), binary);
    assert.match(capturedBinary.exchanges[0].response, /Binary HTTP content/);
  });
  await check('redirect requests and responses remain paired', async () => {
    const captured = await capture('INJ-05', ['-sS', '-L', `${target}/redirect`]);
    assert.equal(captured.exchanges.length, 2);
    assert.match(captured.exchanges[0].request, /^GET \/redirect/);
    assert.match(captured.exchanges[0].response, /^HTTP\/1.1 302/);
    assert.match(captured.exchanges[1].request, /^GET \/hex/);
    assert.match(captured.exchanges[1].response, /^HTTP\/1.1 200/);
  });
  await check('incorrect wrapper syntax is rejected before sending requests', async () => {
    const count = received.length;
    const execution = await run(process.execPath, [wrapper, '--finding-id', 'INJ-06', '--', 'curl', `${target}/hex`], { env: { SHANNON_DELIVERABLES_DIR: dir } });
    assert.equal(execution.code, 2); assert.equal(received.length, count);
  });
  await check('incomplete traces are detected rather than presented as complete', async () => {
    assert.ok(parseCurlTrace('=> Send header, 16 bytes\n0000: 61 62').errors.length);
  });
  await check('single trace blocks with five-digit offsets decode without truncation', async () => {
    const bytes = Buffer.alloc(70000, 'Z');
    const lines = ['<= Recv data, 70000 bytes (0x11170)'];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const hex = [...bytes.subarray(offset, offset + 16)].map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
      lines.push(`${offset.toString(16).padStart(4, '0')}: ${hex.padEnd(47)} ZZZZZZZZZZZZZZZZ`);
    }
    const parsed = parseCurlTrace(lines.join('\n'));
    assert.deepEqual(parsed.errors, []);
    assert.deepEqual(Buffer.from(parsed.parts[0].base64, 'base64'), bytes);
  });

  const plan = { steps: [{ method: 'GET', url: '${BASE_URL}/protected', headers: { Authorization: 'Bearer ${BEARER_TOKEN}', 'X-Evidence': 'INJ-02' }, expect: { status: 200, body_contains: 'private-audit-record INJ-02' } }] };
  const verify = (id, plan, variables = {}) => verifyHttpReplay({ findingId: id, plan, variables, deliverablesDir: dir, targetUrl: target });
  await check('replay preserves empty headers, variable paths and the configured target', async () => {
    const replay = { steps: [{ method: 'GET', url: '${BASE_URL}${PATH}', headers: { yapi: '' }, expect: { status: 200, body_contains: 'ab' } }] };
    const result = await verify('AUTH-90', replay, { PATH: '/hex', BASE_URL: 'http://127.0.0.1:1' });
    assert.ok(result.verification, result.error);
    assert.equal(received.at(-1).headers.yapi, '');
    const rejected = await verify('AUTH-91', replay, { PATH: '@127.0.0.1:1/hex' });
    assert.ok(rejected.error);
  });
  await check('multipart replay sends matching boundary and file content', async () => {
    const replay = { steps: [{ method: 'POST', url: '${BASE_URL}/hex', multipart: [{ name: 'path', value: 'fixture' }, { name: 'file', filename: 'proof.txt', content_type: 'text/plain', value: 'upload fixture' }], expect: { status: 200, body_contains: 'ab' } }] };
    const result = await verify('AUTH-92', replay);
    assert.ok(result.verification, result.error);
    const request = received.at(-1);
    const boundary = /boundary=([^;]+)/.exec(request.headers['content-type'])?.[1];
    assert.ok(boundary);
    assert.ok(request.body.toString().includes(`--${boundary}`));
    assert.match(request.body.toString(), /filename="proof.txt"/);
    assert.match(request.body.toString(), /upload fixture/);
    assert.ok(replayPlanError({ steps: [{ method: 'POST', url: '${BASE_URL}/hex', body: '--b\r\nfixture\r\n--b--\r\n', expect: { status: 200, body_contains: 'ab' } }] }));
    assert.ok(replayPlanError({ steps: [{ method: 'POST', url: '${BASE_URL}/[PARAMS]', expect: { status: 200, body_contains: 'ab' } }] }));
    assert.ok(replayPlanError({ steps: [{ method: 'POST', url: '${BASE_URL}/hex', headers: { 'Content-Type': 'multipart/form-data; boundary=b2' }, body: '--b\r\nfixture\r\n--b--\r\n', expect: { status: 200, body_contains: 'ab' } }] }));
    assert.ok(replayPlanError({ steps: [{ method: 'GET', url: '${BASE_URL}/redirect', follow_redirects: true, expect: { status: 200, body_contains: 'ab' } }] }));
  });
  await check('credential checks distinguish literal values from field names and endpoint names', async () => {
    const login = { steps: [{ method: 'POST', url: '${BASE_URL}/admin', body_json: { username: '${USERNAME}', password: '${PASSWORD}' }, expect: { status: 200, body_contains: 'private record' } }] };
    assert.equal(containsReplaySecret(login, ['admin', 'password', 'a']), false);
    login.steps[0].body_json.password = 'password';
    assert.equal(containsReplaySecret(login, ['password']), true);
  });
  let proof, proofEvidence;
  await check('HTTP 401, wrong impact text, missing assertions and missing variables all fail', async () => {
    assert.ok((await verify('AUTH-01', plan, { BEARER_TOKEN: 'bad' })).error);
    const wrong = structuredClone(plan); wrong.steps[0].expect.body_contains = 'absent-impact';
    assert.ok((await verify('AUTH-02', wrong, { BEARER_TOKEN: 'good' })).error);
    assert.ok((await verify('AUTH-03', { steps: [{ method: 'GET', url: '${BASE_URL}/hex' }] })).error);
    assert.ok((await verify('AUTH-04', plan)).error);
  });
  await check('verified plan records actual HTTP captures and checked assertions', async () => {
    const result = await verify('INJ-02', plan, { BEARER_TOKEN: 'good' });
    assert.ok(result.verification, result.error); proof = result.verification; proofEvidence = result.evidence;
    assert.equal(proof.assertion_count, 1);
    assert.equal(proof.plan_sha256, replayPlanDigest(plan));
    const files = await readdir(`${dir}/http-exchanges/INJ-02`);
    originalCapture = JSON.parse(await readFile(`${dir}/http-exchanges/INJ-02/${files[0]}`, 'utf8'));
    assert.match(originalCapture.exchanges[0].request, /Authorization: Bearer good/);
  });
  await check('JSON credentials are escaped and dynamic JSON/header tokens can be reused', async () => {
    const flow = { steps: [
      { method: 'POST', url: '${BASE_URL}/login', body_json: { username: '${USERNAME}', password: '${PASSWORD}' }, save_json: { TOKEN: 'data.token' } },
      { method: 'GET', url: '${BASE_URL}/protected', headers: { Authorization: 'Bearer ${TOKEN}' }, expect: { status: 200, body_contains: 'private-audit-record' } },
    ] };
    assert.ok((await verify('AUTH-05', flow, { USERNAME: 'fixture-user', PASSWORD: password })).verification);
    assert.ok(received.some((request) => request.url === '/login' && JSON.parse(request.body.toString()).password === password));
    assert.ok((await verify('AUTH-06', { steps: [
      { method: 'GET', url: '${BASE_URL}/cookie', save_headers: { SESSION: 'Set-Cookie' } },
      { method: 'GET', url: '${BASE_URL}/protected', headers: { Cookie: '${SESSION}' }, expect: { status: 200, body_contains: 'private-audit-record' } },
    ] })).verification);
  });
  await check('cleanup runs after assertion failure; failed cleanup rejects verification', async () => {
    const mutation = { steps: [{ method: 'POST', url: '${BASE_URL}/create', expect: { status: 200, body_contains: 'absent-impact' } }], cleanup: [{ method: 'DELETE', url: '${BASE_URL}/created' }] };
    assert.ok((await verify('MISC-01', mutation)).error); assert.equal(created, false);
    mutation.steps[0].expect.body_contains = 'created fixture record';
    mutation.cleanup[0].url = '${BASE_URL}/cleanup-fail';
    assert.match((await verify('MISC-02', mutation)).error, /Cleanup failed/);
    created = false;
  });
  await check('setup and cleanup requests are both traced and cleaned up', async () => {
    const replay = {
      setup: [{ method: 'POST', url: '${BASE_URL}/create' }],
      steps: [{ method: 'POST', url: '${BASE_URL}/create', expect: { status: 200, body_contains: 'created fixture record' } }],
      cleanup: [{ method: 'DELETE', url: '${BASE_URL}/created' }],
    };
    const result = await verify('MISC-03', replay);
    assert.ok(result.verification, result.error);
    assert.equal(result.verification.request_count, 3);
    assert.equal(result.evidence.length, 3);
    assert.ok(result.evidence.every((receipt) => receipt.complete));
    assert.equal(created, false);
  });

  const exploit = { status: 'exploited', vulnerability_id: 'INJ-02', title: 'Private endpoint access', vulnerable_location: '/protected', overview: 'Fixture', severity: 'high', severity_rationale: 'Fixture', impact: 'Reads private record', exploitation_steps: ['Read record'], proof_of_impact: 'private-audit-record', verification_method: 'http', http_evidence_display: 'include', http_evidence_reason: 'The protected record response demonstrates unauthorized access.', http_replay: plan };
  const invoke = async (collector, name, input, signal) => {
    const tool = collector.tools.find((tool) => tool.name === name);
    assert.ok(tool, `Missing tool ${name}`);
    return JSON.parse((await tool.execute('fixture-call', input, signal)).content[0].text);
  };
  const recordOptions = (directory, ids = ['INJ-02', 'INJ-03'], variables = { BEARER_TOKEN: 'good' }) => ({
    deliverablesDir: directory, sourceDir: temporary, targetUrl: target, validIds: new Set(ids),
    verificationPlans: new Map(ids.map((id) => [id, plan])),
    verifyReplay: (findingId, savedPlan) => verifyHttpReplay({
      findingId, plan: savedPlan, variables, deliverablesDir: directory, targetUrl: target,
    }),
  });
  const verdict = (id, status, capture_ids) => ({
    finding_id: id, status, capture_ids, reason: 'Fixture replay verdict',
    frontend_status: 'not_found', frontend_url: null, frontend_trigger: null, frontend_reason: 'Fixture has no UI',
  });
  const evidenceEntry = (base, receipts) => ({
    ...base, http_evidence_display: 'include', http_evidence_ids: receipts.map((item) => item.capture_id),
    http_evidence_receipts: receipts,
  });
  await check('Exploit submits the exact observed request plan without an extra target replay', async () => {
    const collector = createExploitCollector({ vulnClass: 'injection', validIds: new Set(['INJ-02']) });
    const before = received.length;
    assert.equal((await invoke(collector, 'add_exploit', exploit)).status, 'success');
    assert.equal(received.length, before);
    assert.equal(hasVerifiedReplay(collector.getAll()[0]), false);
    assert.deepEqual(collector.tools.map((tool) => tool.name), ['add_exploit']);
    const missing = { ...exploit }; delete missing.http_replay;
    assert.equal((await invoke(createExploitCollector({ vulnClass: 'injection', validIds: new Set(['INJ-02']) }), 'add_exploit', missing)).status, 'error');
  });
  await check('Record requires its own passing host replay and rejects borrowed capture IDs', async () => {
    const collector = createRecordCollector(recordOptions(dir));
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'verified', []))).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'verified', proofEvidence.map((item) => item.capture_id)))).status, 'error');
    const checked = await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-02' });
    assert.equal(checked.status, 'success', checked.message);
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-03', 'verified', checked.captures.map((item) => item.capture_id)))).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'verified', checked.captures.map((item) => item.capture_id)))).status, 'verified');
    assert.ok(collector.getAll()[0].http_replay_verification);
    assert.deepEqual(collector.getAll()[0].http_evidence_receipts, checked.captures);
  });
  await check('Record can correct observed private variables after a failed replay and retry the unchanged plan', async () => {
    const variableDir = `${temporary}/private-replay-variables`;
    await mkdir(variableDir, { mode: 0o700 });
    await writeFile(`${variableDir}/INJ-02.json`, JSON.stringify({ BEARER_TOKEN: 'bad' }), { mode: 0o600 });
    const repairCollector = createRecordCollector({
      ...recordOptions(dir),
      inspectReplayVariables: async (findingId) => Object.keys(await loadReplayVariables(variableDir, findingId)).sort(),
      repairReplayVariables: (findingId, savedPlan, updates) => updateReplayVariables(variableDir, findingId, savedPlan, updates),
      verifyReplay: async (findingId, savedPlan) => {
        const variables = await loadReplayVariables(variableDir, findingId);
        return verifyHttpReplay({ findingId, plan: savedPlan, variables, deliverablesDir: dir, targetUrl: target });
      },
    });
    assert.equal((await invoke(repairCollector, 'update_replay_variables', { finding_id: 'INJ-02', variables: { BEARER_TOKEN: 'good' } })).status, 'error');
    const first = await invoke(repairCollector, 'verify_http_replay', { finding_id: 'INJ-02' });
    assert.equal(first.status, 'error');
    assert.ok(first.captures.length);
    const inspected = await invoke(repairCollector, 'inspect_replay_variables', { finding_id: 'INJ-02' });
    assert.deepEqual(inspected.saved_variable_names, ['BEARER_TOKEN']);
    assert.doesNotMatch(JSON.stringify(inspected), /good|bad/);
    const corrected = await invoke(repairCollector, 'update_replay_variables', { finding_id: 'INJ-02', variables: { BEARER_TOKEN: 'good' } });
    assert.equal(corrected.status, 'success', corrected.message);
    assert.deepEqual(corrected.updated_variable_names, ['BEARER_TOKEN']);
    assert.doesNotMatch(JSON.stringify(corrected), /good|bad/);
    assert.equal((await stat(`${variableDir}/INJ-02.json`)).mode & 0o777, 0o600);
    const retry = await invoke(repairCollector, 'verify_http_replay', { finding_id: 'INJ-02' });
    assert.equal(retry.status, 'success', retry.message);
    assert.equal(retry.verification.assertion_count, 1);
    assert.equal((await invoke(repairCollector, 'update_replay_variables', { finding_id: 'INJ-02', variables: { PATH: '/hex' } })).status, 'error');
    const extracted = { steps: [
      { method: 'POST', url: '${BASE_URL}/login', save_json: { TOKEN: 'data.token' } },
      { method: 'GET', url: '${BASE_URL}/protected', headers: { Authorization: 'Bearer ${TOKEN}' }, expect: { status: 200, body_contains: 'private-audit-record' } },
    ] };
    await assert.rejects(updateReplayVariables(variableDir, 'INJ-02', extracted, { TOKEN: 'forged' }), /extracted from an earlier response/);
  });
  const renumbered = buildRenumberMap([{ ...exploit, http_evidence_receipts: proofEvidence, http_evidence_ids: proofEvidence.map((receipt) => receipt.capture_id), http_replay_verification: proof, reproduction_script: '# capture_curl INJ-02\ntrue' }], 'injection');
  await check('renumbering keeps replay payloads and verification digests unchanged', async () => {
    assert.equal(renumbered.renumbered[0].vulnerability_id, 'INJ-01');
    assert.deepEqual(renumbered.renumbered[0].http_replay, plan);
    assert.ok(hasVerifiedReplay(renumbered.renumbered[0]));
    assert.match(renumbered.renumbered[0].reproduction_script, /INJ-02/);
  });
  const gitEnv = { GIT_AUTHOR_NAME: 'HTTP fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'HTTP fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' };
  async function commit(files) {
    for (const [file, data] of Object.entries(files)) await writeFile(`${dir}/${file}`, JSON.stringify(data, null, 2));
    for (const args of [['add', '--', ...Object.keys(files)], ['commit', '-m', 'HTTP fixture']]) {
      const result = await run('git', args, { cwd: dir, env: gitEnv }); assert.equal(result.code, 0, result.stderr);
    }
  }
  assert.equal((await run('git', ['init'], { cwd: dir })).code, 0);
  await commit({ 'injection_exploit_collector.json': [{ ...renumbered.renumbered[0], vulnerability_id: 'INJ-02' }], 'injection_renumber_map.json': { map: { 'INJ-02': 'INJ-01' } }, 'injection_exploit_collector_renumbered.json': renumbered.renumbered });
  let findings;
  await check('report joins correct evidence, redacts configured credentials and survives compaction', async () => {
    findings = await attachHttpEvidence([{ finding_id: 'INJ-01', title: 'Fixture', category: 'Injection', severity: 'high', overview: 'Fixture', impact: 'Fixture', remediation: 'Fixture', vulnerable_location: '/protected', owasp_category: 'A01:2025 — Broken Access Control', exploitation_steps: [{ title: 'Preserved step', items: [{ kind: 'prose', text: 'Original exploitation setup' }] }], proof_of_impact: [{ kind: 'prose', text: 'Model evidence fragment retained for audit' }] }], dir,
      configuredCaptureRedactions({ username: 'fixture-user', password: 'good' }));
    const section = findings[0].additional_sections.find((section) => section.heading === '捕获的 HTTP 请求与响应');
    assert.match(JSON.stringify(section), /Bearer good/);
    assert.match(JSON.stringify(section), /INJ-02/);
    const compacted = deepRemapStrings(findings, new Map([['INJ-02', 'INJ-01']]));
    assert.deepEqual(compacted[0].additional_sections[0], section);
    assert.match(originalCapture.exchanges[0].request, /Bearer good/);
    assert.match(JSON.stringify(findings), /通过宿主验证/);
    const appendix = await renderCapturedHttpEvidence(dir, 'injection', renumbered.oldToNew);
    assert.equal((appendix.match(/- INJ-01:/g) ?? []).length, 1);
    assert.doesNotMatch(appendix, /GET \/hex/);
    const markdown = renderReport({ report_meta: { target, assessment_date: '2026-10-14', scope: 'Fixture', executive_summary: 'Fixture' }, findings });
    assert.match(markdown, /GET \/protected HTTP/);
    assert.match(markdown, /自动化重放覆盖/);
  });
  await check('Markdown and PDF use paired HTTP evidence once after the original exploitation steps', async () => {
    const report = { report_meta: { target, assessment_date: '2026-10-14', scope: 'Fixture', executive_summary: 'Fixture' }, findings };
    const markdown = renderReport(report);
    assert.equal((markdown.match(/^#### 捕获的 HTTP 请求与响应$/gm) ?? []).length, 1);
    assert.ok(markdown.indexOf('Original exploitation setup') < markdown.indexOf('捕获的 HTTP 请求与响应'));
    assert.ok(markdown.indexOf('捕获的 HTTP 请求与响应') < markdown.indexOf('**Remediation:**'));
    assert.doesNotMatch(markdown, /Proof of Impact|Model evidence fragment/);
    const adapted = adaptReportToTypst(report).findings[0];
    assert.ok(!Object.hasOwn(adapted, 'proofOfImpact'));
    assert.equal(adapted.exploitationSteps[0].items[0].text, 'Original exploitation setup');
    const expected = findings[0].additional_sections.find((section) => section.heading === '捕获的 HTTP 请求与响应');
    assert.deepEqual(adapted.capturedHttpEvidence.items.map((item) => item.kind === 'code' ? item.block.content : item.text), expected.items.map((item) => item.kind === 'code' ? item.block.content : item.text));
    assert.ok(!adapted.additionalSections.some((section) => section.heading === '捕获的 HTTP 请求与响应'));
    assert.equal(findings[0].proof_of_impact[0].text, 'Model evidence fragment retained for audit');
  });
  await check('browser evidence survives Markdown/PDF while omitted HTTP has no placeholder section', async () => {
    const finding = { ...findings[0], http_evidence_display: 'omit', verification_method: 'browser', additional_sections: [{ heading: '浏览器验证证据', items: [{ kind: 'prose', text: 'Actual browser observation: document.title became XSS_EXEC after clicking Login.' }] }] };
    const report = { report_meta: { target, assessment_date: '2026-10-14', scope: 'Fixture', executive_summary: 'Fixture' }, findings: [finding] };
    const markdown = renderReport(report);
    assert.match(markdown, /Actual browser observation/);
    assert.doesNotMatch(markdown, /捕获的 HTTP 请求与响应|没有已关联|缺少.*HTTP/);
    const adapted = adaptReportToTypst(report).findings[0];
    assert.equal(adapted.capturedHttpEvidence, undefined);
    assert.match(adapted.verificationEvidence.items[0].text, /Actual browser observation/);
  });
  await check('report credential projection preserves JSON keys, endpoint paths, and session cookies', async () => {
    const credentialCapture = await captureHttpRequest({ deliverablesDir: dir, findingId: 'AUTH-07', curlArguments: ['-sS', '-H', 'Content-Type: application/json', '-H', 'Cookie: session=admin', '--data-binary', JSON.stringify({ username: 'admin', password: 'password' }), `${target}/login`] });
    await commit({ 'auth_renumber_map.json': { map: { 'AUTH-07': 'AUTH-01' } } });
    const auth = { vulnerability_id: 'AUTH-07', http_evidence_display: 'include', http_evidence_ids: [credentialCapture.receipt.capture_id], http_evidence_receipts: [credentialCapture.receipt] };
    await commit({ 'auth_exploit_collector.json': [auth], 'auth_exploit_collector_renumbered.json': [{ ...auth, vulnerability_id: 'AUTH-01' }] });
    const projected = await attachHttpEvidence([{ finding_id: 'AUTH-01', status: 'exploited' }], dir, configuredCaptureRedactions({ username: 'admin', password: 'password' }));
    const section = projected[0].additional_sections.find((section) => section.heading === '捕获的 HTTP 请求与响应');
    const request = section.items.find((item) => item.kind === 'code').block.content;
    assert.match(request, /Cookie: session=admin/);
    assert.match(request, /"username":"\$username","password":"\$password"/);
    assert.match(request, /POST \/login HTTP/);
  });
  await check('HTTP content containing Markdown fences stays inside its evidence block', async () => {
    const content = 'HTTP/1.1 200 OK\r\n\r\n```\nraw body\n```';
    const report = renderReport({ report_meta: { target, assessment_date: '2026-10-14', scope: 'Fixture', executive_summary: 'Fixture' }, findings: [{ ...findings[0], additional_sections: [{ heading: 'Captured', items: [{ kind: 'code', block: { language: 'http', content } }] }] }] });
    assert.ok(report.includes('````http\n' + content + '\n````'));
  });
  await check('uncommitted collector edits cannot alter replay publication', async () => {
    await writeFile(`${dir}/injection_exploit_collector_renumbered.json`, '[]');
    const script = await writeReproductionScript(dir, target, new Set(['INJ-01']));
    assert.match(await readFile(script, 'utf8'), /# INJ-01:/);
  });
  await check('explicit optional impact verification works, fails on 401, and separates repeat runs', async () => {
    const script = await writeReproductionScript(dir, target, new Set(['INJ-01']));
    const output = `${temporary}/replay-output`;
    const before = received.length;
    const instructions = await run('bash', [script, '--requirements', 'INJ-01']);
    assert.match(instructions.stdout, /BEARER_TOKEN/); assert.match(instructions.stdout, /获取方式/);
    assert.match(instructions.stdout, /不包含 Authorization: 或 Bearer/);
    const missing = await run('bash', [script, '--verify', 'INJ-01'], { env: { BEARER_TOKEN: '', OUTPUT_DIR: `${temporary}/verify-missing` } });
    assert.equal(missing.code, 2); assert.match(missing.stderr, /export BEARER_TOKEN=/);
    assert.equal(received.length, before);
    await assert.rejects(stat(`${temporary}/verify-missing`), { code: 'ENOENT' });
    const passed = await run('bash', [script, '--verify', 'INJ-01'], { env: { ...noProxy, BEARER_TOKEN: 'good', OUTPUT_DIR: output } });
    assert.equal(passed.code, 0, passed.stdout + passed.stderr); assert.match(passed.stdout, /INJ-01: passed/);
    const failed = await run('bash', [script, '--verify', 'INJ-01'], { env: { ...noProxy, BEARER_TOKEN: 'bad', OUTPUT_DIR: output } });
    assert.equal(failed.code, 1); assert.match(failed.stdout, /INJ-01: failed/);
    assert.doesNotMatch(failed.stdout, /: passed/);
    const runs = await readdir(output); assert.equal(runs.length, 2);
    for (const runDir of runs) {
      const files = await readdir(`${output}/${runDir}/INJ-01`);
      for (const name of ['001.trace', '001.headers', '001.body', 'result.json']) assert.ok(files.includes(name));
      assert.equal((await stat(`${output}/${runDir}/INJ-01/001.trace`)).mode & 0o777, 0o600);
    }
  });
  await check('customer output includes executable standalone replay script', async () => {
    await writeFile(`${dir}/comprehensive_security_assessment_report.md`, 'Fixture report');
    const result = await surfaceReportOutputs({ deliverablesDir: dir, customerDir: `${temporary}/customer`, logger: { info() {}, warn() {} } });
    assert.ok(result.surfaced.includes('reproduce.sh'));
    assert.equal((await stat(`${temporary}/customer/reproduce.sh`)).mode & 0o777, 0o700);
  });
  await check('report-only finalization generates replay without target requests and repairs it on adoption', async () => {
    for (const args of [['config', 'user.name', 'HTTP fixture'], ['config', 'user.email', 'fixture@example.invalid']]) {
      const result = await run('git', args, { cwd: dir }); assert.equal(result.code, 0, result.stderr);
    }
    await commit({
      'report.json': {
        report_meta: { target: `${target}/login/`, assessment_date: '2026-10-15', scope: 'Fixture', executive_summary: 'Fixture' },
        findings: [findings[0], { ...findings[0], finding_id: 'INJ-03', additional_sections: [] }],
      },
      'injection_exploit_collector_renumbered.json': [
        ...renumbered.renumbered,
        { ...renumbered.renumbered[0], vulnerability_id: 'INJ-99' },
        { ...exploit, vulnerability_id: 'INJ-03' },
      ],
    });
    const script = `${dir}/reproduce.sh`;
    await unlink(script);
    const options = {
      deliverablesDir: dir, exploit: true, partialReasons: [], reportConfig: { sarif: false },
      workspaceName: 'report-recovery-fixture', logger: { info() {}, warn() {}, error() {} },
      renderPdf: async () => { throw new Error('PDF intentionally unavailable'); },
    };
    const before = received.length;
    const finalized = await finalizeReport(options);
    assert.equal(finalized.pdfGenerated, false);
    const contents = await readFile(script, 'utf8');
    assert.match(contents, /# INJ-01:/);
    assert.match(contents, /# INJ-03:/); assert.doesNotMatch(contents, /# INJ-99:/);
    assert.equal((await stat(script)).mode & 0o777, 0o700);
    assert.equal((await run('bash', ['-n', script])).code, 0);
    await unlink(script);
    const repeated = await finalizeReport(options);
    assert.equal(repeated.commit.alreadyCommitted, true);
    assert.equal(repeated.commit.commitHash, finalized.commit.commitHash);
    assert.equal(await readFile(script, 'utf8'), contents);
    assert.equal(received.length, before, 'Generating or repairing the script must not send HTTP requests');
    // A write failure must not masquerade as successful report recovery; retry restores it.
    await unlink(script);
    await mkdir(script);
    try {
      await assert.rejects(finalizeReport(options), { code: 'EISDIR' });
    } finally {
      await rmdir(script);
    }
    await finalizeReport(options);
    // Exercise only the loopback fixture, including the default origin for a /login/ target.
    const replayed = await run('bash', [script, '--verify', 'INJ-01'], { env: { ...noProxy, BASE_URL: '', BEARER_TOKEN: 'good', OUTPUT_DIR: `${temporary}/recovered-replay` } });
    assert.equal(replayed.code, 0, replayed.stdout + replayed.stderr);
    assert.match(replayed.stdout, /INJ-01: passed/);
  });
  await check('legacy Bash is never executed and listing never claims reproduction success', async () => {
    const changed = structuredClone(renumbered.renumbered[0]); changed.http_replay.steps[0].url += '?changed';
    assert.equal(hasVerifiedReplay(changed), false);
    await commit({ 'injection_exploit_collector_renumbered.json': [{ status: 'exploited', vulnerability_id: 'INJ-01', reproduction_script: '# capture_curl INJ-01\ntrue' }] });
    const script = await writeReproductionScript(dir, target, new Set(['INJ-01']));
    const result = await run('bash', [script], { env: { OUTPUT_DIR: `${temporary}/empty-replay` } });
    assert.equal(result.code, 0); assert.doesNotMatch(result.stdout, /: passed/); assert.match(result.stdout, /0 captured commands/);
  });

  const strictDir = `${temporary}/strict-deliverables`;
  await mkdir(strictDir);
  let actualReceipt, strictRenumbered;
  const actualExploit = { ...exploit, http_replay: null, http_replay_unavailable_reason: 'Manual proof fixture' };
  await check('Record captures one actual request; capture alone cannot assert verified impact', async () => {
    const collector = createRecordCollector(recordOptions(strictDir));
    const before = received.filter((request) => request.url === '/create').length;
    const result = await invoke(collector, 'capture_http_request', { finding_id: 'INJ-02', curl_arguments: ['-sS', '-X', 'POST', `${target}/create`] });
    assert.equal(result.status, 'success'); assert.equal(result.complete, true);
    assert.equal(received.filter((request) => request.url === '/create').length - before, 1);
    actualReceipt = result;
    const saved = await readVerifiedHttpEvidence(strictDir, result);
    assert.match(saved.exchanges[0].request, /^POST \/create HTTP/);
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'verified', [result.capture_id]))).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'failed', [result.capture_id]))).status, 'failed');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'failed', [result.capture_id]))).status, 'error');
  });
  await check('Record blocks unknown IDs, cross-origin requests, redirects, literal auth and absent plans', async () => {
    const options = recordOptions(strictDir);
    const collector = createRecordCollector(options), before = received.length;
    assert.equal((await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-99' })).status, 'error');
    assert.equal((await invoke(collector, 'capture_http_request', { finding_id: 'INJ-99', curl_arguments: ['-sS', `${target}/hex`] })).status, 'error');
    assert.equal((await invoke(collector, 'capture_http_request', { finding_id: 'INJ-02', curl_arguments: ['--url', 'https://other.invalid/'] })).status, 'error');
    for (const saved of [undefined, { steps: [{ ...plan.steps[0], follow_redirects: true }] }, { steps: [{ ...plan.steps[0], headers: { Authorization: 'Bearer literal-secret' } }] }]) {
      const entry = createRecordCollector({ ...options, verificationPlans: new Map(saved ? [['INJ-02', saved]] : []) });
      assert.equal((await invoke(entry, 'verify_http_replay', { finding_id: 'INJ-02' })).status, 'error');
    }
    assert.equal(received.length, before);
  });
  await check('failed Record assertions retain diagnostic packets and never grant verified status', async () => {
    const collector = createRecordCollector(recordOptions(strictDir, ['INJ-03'], { BEARER_TOKEN: 'bad' }));
    const replay = await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-03' });
    assert.equal(replay.status, 'error'); assert.ok(replay.captures.length);
    const ids = replay.captures.map((item) => item.capture_id);
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-03', 'verified', ids))).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-03', 'failed', ids))).status, 'failed');
  });
  await check('Record checks frontend consistency and requires every replay packet', async () => {
    const collector = createRecordCollector(recordOptions(strictDir));
    const checked = await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-02' });
    assert.equal(checked.status, 'success');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'verified', []))).status, 'error');
    const input = verdict('INJ-02', 'verified', checked.captures.map((item) => item.capture_id));
    assert.equal((await invoke(collector, 'record_verification', { ...input, frontend_status: 'available' })).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', { ...input, frontend_url: `${target}/` })).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', input)).status, 'verified');
  });
  await check('Record enforces three attempts and retains all failed diagnostics without an agent verdict', async () => {
    const collector = createRecordCollector(recordOptions(strictDir, ['INJ-03'], { BEARER_TOKEN: 'bad' }));
    const before = received.length;
    for (let attempt = 0; attempt < 3; attempt++)
      assert.equal((await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-03' })).status, 'error');
    const afterLimit = received.length;
    assert.ok(afterLimit > before);
    for (let attempt = 0; attempt < 5; attempt++) {
      const denied = await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-03' });
      assert.equal(denied.status, 'error');
      assert.match(denied.message, /limit/);
    }
    assert.equal(received.length, afterLimit, 'exhausted retries must not send additional target requests');
    const failure = collector.getAll()[0];
    assert.equal(failure.status, 'failed');
    assert.equal(failure.failure_kind, 'retry_exhausted');
    assert.equal(failure.attempts, 3);
    assert.deepEqual(failure.replay_history.map((attempt) => attempt.attempt), [1, 2, 3]);
    assert.ok(failure.replay_history.every((attempt) => attempt.error && attempt.capture_ids.length));
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-03', 'failed', []))).status, 'failed');
    assert.equal(collector.getAll().length, 1, 'a submitted verdict replaces the automatic failure');
  });
  await check('Record serializes a finding replay and prevents resending after success', async () => {
    let release, executions = 0;
    const collector = createRecordCollector({
      ...recordOptions(strictDir),
      verifyReplay: async () => {
        executions++;
        await new Promise((resolve) => { release = resolve; });
        return { error: 'fixture failure' };
      },
    });
    const pending = invoke(collector, 'verify_http_replay', { finding_id: 'INJ-02' });
    assert.equal((await invoke(collector, 'verify_http_replay', { finding_id: 'INJ-02' })).status, 'error');
    assert.equal((await invoke(collector, 'record_verification', verdict('INJ-02', 'failed', []))).status, 'error');
    assert.equal(executions, 1);
    release();
    await pending;
    const successful = createRecordCollector(recordOptions(strictDir));
    const replay = await invoke(successful, 'verify_http_replay', { finding_id: 'INJ-02' });
    assert.equal(replay.status, 'success');
    const before = received.length;
    assert.equal((await invoke(successful, 'verify_http_replay', { finding_id: 'INJ-02' })).status, 'error');
    assert.equal(received.length, before);
    assert.equal((await invoke(successful, 'record_verification', verdict('INJ-02', 'verified', replay.captures.map((capture) => capture.capture_id)))).status, 'verified');
    assert.equal(successful.getAll()[0].attempts, 1);
  });
  await check('failed transfers, cancellation and timeouts retain provenance without resending', async () => {
    const failed = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', '--connect-timeout', '1', 'http://127.0.0.1:1/'] });
    assert.equal(failed.receipt.complete, false); assert.notEqual(failed.receipt.exit_code, 0);
    await stat(`${strictDir}/${failed.receipt.file}`);
    const controller = new AbortController(); controller.abort(); const before = received.length;
    await assert.rejects(captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', `${target}/hex`], signal: controller.signal }), /cancelled/);
    assert.equal(received.length, before);
    const slowBefore = received.filter((request) => request.url === '/slow').length;
    const timed = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', `${target}/slow`], timeoutSeconds: 1 });
    assert.equal(timed.receipt.exit_code, 124); assert.equal(timed.receipt.complete, false);
    assert.match((await readVerifiedHttpEvidence(strictDir, timed.receipt)).exchanges[0].request, /GET \/slow HTTP/);
    assert.equal(received.filter((request) => request.url === '/slow').length - slowBefore, 1);
  });
  await check('capture argv stays literal and cannot disable tracing using config, --, or --trace options', async () => {
    const before = received.length;
    for (const args of [['-K', '/tmp/fixture-curlrc'], ['-skK/tmp/fixture-curlrc'], ['--confi=/tmp/fixture-curlrc'], ['--', `${target}/hex`], ['--trace-ascii', '/tmp/trace'], ['curl', `${target}/hex`]]) {
      await assert.rejects(captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: args }));
    }
    assert.equal(received.length, before);
    const result = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sSv', '--get', '--data-urlencode', 'payload=$(echo unwanted);`literal`', `${target}/hex`] });
    assert.ok((await readVerifiedHttpEvidence(strictDir, result.receipt)).exchanges[0].request.includes('%24%28echo'));
    const literal = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', '--data-raw', '--trace-ascii', `${target}/create`] });
    assert.equal(literal.receipt.complete, true); assert.equal(received.at(-1).body.toString(), '--trace-ascii');
  });
  await check('renumbered and compacted evidence keeps original capture ownership and rejects tampering', async () => {
    const source = evidenceEntry(actualExploit, [actualReceipt]);
    strictRenumbered = buildRenumberMap([source], 'injection');
    assert.equal(strictRenumbered.renumbered[0].vulnerability_id, 'INJ-01');
    assert.equal(strictRenumbered.renumbered[0].http_evidence_receipts[0].finding_id, 'INJ-02');
    await commitAt(strictDir, { 'injection_exploit_collector.json': [source], 'injection_exploit_collector_renumbered.json': strictRenumbered.renumbered, 'injection_renumber_map.json': { map: Object.fromEntries(strictRenumbered.oldToNew) } });
    const [report] = await attachHttpEvidence([{ ...findings[0], finding_id: 'INJ-01' }], strictDir);
    assert.match(JSON.stringify(report.additional_sections), /POST \/create HTTP/);
    assert.match(JSON.stringify(report.additional_sections), new RegExp(actualReceipt.capture_id));
    const file = `${strictDir}/${actualReceipt.file}`, original = await readFile(file, 'utf8');
    await writeFile(file, original + ' ');
    await assert.rejects(attachHttpEvidence([findings[0]], strictDir), /modified after capture/);
    await writeFile(file, original);
  });

  async function commitAt(directory, files) {
    await mkdir(directory, { recursive: true });
    for (const [name, value] of Object.entries(files)) await writeFile(`${directory}/${name}`, JSON.stringify(value, null, 2));
    for (const args of [['init'], ['add', '--', ...Object.keys(files)], ['commit', '-m', 'Evidence decisions fixture']]) {
      const result = await run('git', args, { cwd: directory, env: gitEnv }); assert.equal(result.code, 0, result.stderr);
    }
  }
  await check('report rejects unreviewed, omitted and browser-only entries without Record HTTP proof', async () => {
    for (const display of [undefined, 'omit']) {
      const legacy = { ...exploit, vulnerability_id: 'INJ-02', verification_method: 'browser', http_evidence_display: display };
      await commit({ 'injection_exploit_collector.json': [legacy], 'injection_exploit_collector_renumbered.json': [{ ...legacy, vulnerability_id: 'INJ-01' }] });
      await assert.rejects(attachHttpEvidence([findings[0]], dir), /no complete captured HTTP/);
    }
  });
  async function exportCapture(directory, curlArguments, secrets) {
    const captured = await captureHttpRequest({ deliverablesDir: directory, findingId: 'INJ-02', curlArguments, cwd: temporary, secrets });
    assert.equal(captured.receipt.complete, true);
    const numbered = buildRenumberMap([evidenceEntry(actualExploit, [captured.receipt])], 'injection');
    await commitAt(directory, {
      'injection_exploit_collector.json': [evidenceEntry(actualExploit, [captured.receipt])],
      'injection_exploit_collector_renumbered.json': numbered.renumbered,
      'injection_renumber_map.json': { map: Object.fromEntries(numbered.oldToNew) },
    });
    return captured.receipt;
  }
  await check('captured commands enter manual reproduction without an extra replay, preserving bytes and paths', async () => {
    const directory = `${temporary}/manual-capture`, bodyFile = `${temporary}/payload fixture.bin`;
    const bytes = Buffer.from([0, 255, 65, 10, 39, 36, 96]);
    await writeFile(bodyFile, bytes);
    await exportCapture(directory, ['-sS', '-H', 'Authorization: Bearer good', '--data-binary', '@payload fixture.bin', `${target}/app/create?literal=%24%28hello%29`]);
    const originalRequest = received.at(-1);
    const before = received.length;
    const script = await writeReproductionScript(directory, `${target}/login/`, new Set(['INJ-01']));
    assert.equal(received.length, before);
    const listed = await run('bash', [script]); assert.equal(listed.code, 0); assert.match(listed.stdout, /INJ-01/); assert.equal(received.length, before);
    const shown = await run('bash', [script, '--show', 'INJ-01']); assert.match(shown.stdout, /Recorded command/); assert.doesNotMatch(shown.stdout, /Bearer good/);
    const content = await readFile(script, 'utf8');
    const encoded = content.match(/manual_main\(json.loads\(base64.b64decode\('([^']+)'\)\)\)/);
    // Parse the export as a reviewer would; base64 is transport encoding, not redaction.
    const exported = JSON.parse(Buffer.from(encoded[1], 'base64').toString());
    assert.ok(!JSON.stringify(exported).includes('Bearer good'));
    const variable = exported[0].commands[0].argv.find((arg) => typeof arg === 'object').variable;
    const missing = await run('bash', [script, 'INJ-01'], { env: { OUTPUT_DIR: `${temporary}/manual-results` } });
    assert.equal(missing.code, 2); assert.equal(received.length, before);
    await writeFile(bodyFile, 'changed after capture');
    const replayed = await run('bash', [script, 'INJ-01'], { env: { ...noProxy, [variable]: 'Authorization: Bearer good', OUTPUT_DIR: `${temporary}/manual-results`, BASE_URL: target } });
    assert.equal(replayed.code, 0, replayed.stderr);
    assert.equal(received.length, before + 1); assert.equal(received.at(-1).url, originalRequest.url);
    assert.equal(received.at(-1).method, originalRequest.method); assert.deepEqual(received.at(-1).body, bytes);
    assert.match(replayed.stdout, /command_completed/); assert.doesNotMatch(replayed.stdout, /: passed/);
    const transport = await run('bash', [script, 'INJ-01'], { env: { ...noProxy, [variable]: 'Authorization: Bearer good', BASE_URL: 'http://127.0.0.1:1', OUTPUT_DIR: `${temporary}/manual-results` } });
    assert.equal(transport.code, 1);
  });
  await check('operator guidance preserves header meaning and reports all missing inputs before requests', async () => {
    const directory = `${temporary}/input-guidance`;
    await exportCapture(directory, ['-sS', '-H', 'Cookie: session=good', '-HAuthorization: Bearer good', `${target}/protected`]);
    const script = await writeReproductionScript(directory, target, new Set(['INJ-01']));
    const content = await readFile(script, 'utf8');
    const exported = JSON.parse(Buffer.from(content.match(/manual_main\(json.loads\(base64.b64decode\('([^']+)'\)\)\)/)[1], 'base64').toString());
    const inputs = exported[0].required_inputs;
    const cookie = inputs.find((input) => input.header_name === 'Cookie');
    const bearer = inputs.find((input) => input.header_name === 'Authorization');
    assert.equal(cookie.variable, 'INJ_01_COMMAND_1_HEADER_1');
    assert.equal(cookie.example, 'Cookie: session=<COOKIE_VALUE>');
    assert.equal(bearer.example, 'Authorization: Bearer <HEADER_VALUE>');
    assert.doesNotMatch(JSON.stringify(exported), /session=good|Bearer good/);
    const before = received.length;
    const shown = await run('bash', [script, '--show', 'INJ-01']);
    const help = await run('bash', [script, '--requirements', 'INJ-01']);
    for (const result of [shown, help]) {
      assert.equal(result.code, 0); assert.match(result.stdout, /Cookie 请求头/);
      assert.match(result.stdout, /F12 → Network/); assert.match(result.stdout, /Request Headers/);
      assert.match(result.stdout, /export INJ_01_COMMAND_1_HEADER_1='Cookie: session=<COOKIE_VALUE>'/);
      assert.doesNotMatch(result.stdout, /session=good|Bearer good/);
    }
    const environment = { [cookie.variable]: '', [bearer.variable]: '', OUTPUT_DIR: `${temporary}/guidance-missing` };
    const missing = await run('bash', [script, 'INJ-01'], { env: environment });
    assert.equal(missing.code, 2);
    for (const input of inputs) assert.ok(missing.stderr.includes(input.variable));
    assert.match(missing.stderr, /获取方式/); assert.match(missing.stderr, /填写格式/); assert.match(missing.stderr, /设置示例/);
    await assert.rejects(stat(environment.OUTPUT_DIR), { code: 'ENOENT' });
    const malformed = await run('bash', [script, 'INJ-01'], { env: { ...environment, [cookie.variable]: 'session=good', [bearer.variable]: 'Authorization: Bearer good' } });
    assert.equal(malformed.code, 2); assert.match(malformed.stderr, /必须以 Cookie: 开头/);
    assert.doesNotMatch(malformed.stderr, /session=good|Bearer good/);
    assert.equal(received.length, before);
    const replayed = await run('bash', [script, 'INJ-01'], { env: { ...noProxy, ...environment, [cookie.variable]: 'Cookie: session=good', [bearer.variable]: 'Authorization: Bearer good' } });
    assert.equal(replayed.code, 0, replayed.stderr); assert.equal(received.length, before + 1);
    assert.equal(received.at(-1).headers.cookie, 'session=good');
    assert.equal(received.at(-1).headers.authorization, 'Bearer good');
    assert.doesNotMatch(replayed.stdout + replayed.stderr, /session=good|Bearer good/);
  });
  await check('input guidance covers values, files and extracted verification variables without exporting secrets', async () => {
    const describe = (option, value) => describeArgumentInput('FIXTURE_INPUT', { option, value, index: 1, prefix: '' });
    assert.equal(describe('cookie', 'session=private-value; other=another-value').example, 'session=<COOKIE_VALUE>; other=<COOKIE_VALUE>');
    assert.match(describe('cookie', 'session=private-value').format, /不包含 Cookie:/);
    for (const option of ['oauth2-bearer', 'user', 'proxy-user', 'url', 'data-raw', 'form', 'stdin', 'proxy']) {
      const input = describe(option, 'private-value');
      assert.ok(input.source && input.format && input.example); assert.ok(!JSON.stringify(input).includes('private-value'));
    }
    assert.equal(describeFileInput('INPUT_FILE', '/fixture/body.json').file, true);
    const inputs = describeVerificationInputs({ steps: [
      { method: 'POST', url: '${BASE_URL}/login', body_json: { username: '${USERNAME}', password: '${PASSWORD}', otp: '${OTP}' }, save_json: { DYNAMIC_TOKEN: 'data.token' } },
      { method: 'GET', url: '${BASE_URL}/protected', headers: { Cookie: '${COOKIE}', Authorization: 'Bearer ${DYNAMIC_TOKEN}' } },
    ] });
    assert.deepEqual(inputs.map((input) => input.variable), ['COOKIE', 'USERNAME', 'PASSWORD', 'OTP']);
    assert.match(inputs[0].format, /不包含 Cookie:/);
  });
  await check('sensitive bodies are parameterized without altering JSON keys or expanding shell text', async () => {
    const directory = `${temporary}/body-capture`, secret = 'quote"\n$HOME;`literal`';
    const body = JSON.stringify({ username: 'fixture-user', password: secret, payload: '$(do-not-execute)' });
    await exportCapture(directory, ['-sS', '--data-raw', body, `${target}/create`], [secret, 'fixture-user']);
    const script = await writeReproductionScript(directory, target, new Set(['INJ-01']));
    const source = await readFile(script, 'utf8');
    const exported = JSON.parse(Buffer.from(source.match(/manual_main\(json.loads\(base64.b64decode\('([^']+)'\)\)\)/)[1], 'base64').toString());
    assert.ok(!JSON.stringify(exported).includes(secret)); assert.ok(!JSON.stringify(exported).includes('fixture-user'));
    const variable = exported[0].commands[0].argv.find((arg) => typeof arg === 'object').variable;
    const result = await run('bash', [script, '--all'], { env: { ...noProxy, [variable]: body, OUTPUT_DIR: `${temporary}/body-results` } });
    assert.equal(result.code, 0, result.stderr); assert.equal(received.at(-1).body.toString(), body);
  });

  await check('multipart snapshots preserve filenames and unknown options stay explicitly manual-only', async () => {
    const directory = `${temporary}/multipart-capture`, input = `${temporary}/original-name.txt`;
    await writeFile(input, 'original multipart bytes');
    await exportCapture(directory, ['-sS', '-F', 'upload=@original-name.txt', `${target}/create`]);
    const script = await writeReproductionScript(directory, target, new Set(['INJ-01']));
    await unlink(input);
    const result = await run('bash', [script, 'INJ-01'], { env: { ...noProxy, OUTPUT_DIR: `${temporary}/multipart-results` } });
    assert.equal(result.code, 0, result.stderr); assert.match(received.at(-1).body.toString(), /filename="original-name.txt"/);
    assert.match(received.at(-1).body.toString(), /original multipart bytes/);
    const manual = await captureHttpRequest({ deliverablesDir: directory, findingId: 'INJ-03', curlArguments: ['-sS', '--limit-rate', '100000', `${target}/hex`] });
    const record = await readVerifiedHttpEvidence(directory, manual.receipt);
    assert.ok(record.invocation.manual_reasons.length);
  });
  await check('URL query tokens and proxy credentials are operator variables even without configured secrets', async () => {
    const invocation = await snapshotCurlInvocation(['--url-query', 'access_token=private-session', '--proxy', 'http://user:pass@localhost:1', `${target}/hex`], temporary, 120);
    assert.ok(invocation.variables['1']); assert.ok(invocation.variables['3']);
    assert.equal(invocation.argv[1], 'access_token=private-session');
  });
  await check('offline historical correction preserves source receipts and refuses overwrite without target requests', async () => {
    const originalReport = `${temporary}/historical-report.json`, decisionFile = `${temporary}/historical-decisions.json`, destination = `${temporary}/corrected-history`;
    await writeFile(originalReport, JSON.stringify({ report_meta: { target, assessment_date: '2026-10-15', scope: 'Fixture', executive_summary: 'Original report' }, findings: [findings[0]] }));
    await writeFile(decisionFile, JSON.stringify({
      'INJ-01': { verification_method: 'http', http_evidence_display: 'include', http_evidence_reason: 'Original captured request.', source_files: [path.basename(actualReceipt.file)] },
    }));
    const before = received.length, originalCollector = await readFile(`${strictDir}/injection_exploit_collector.json`, 'utf8');
    const args = [`${temporary}/dist/scripts/repair-evidence-report.js`, '--source', strictDir, '--report', originalReport, '--output', destination, '--decisions', decisionFile, '--no-pdf'];
    const repaired = await run(process.execPath, args);
    assert.equal(repaired.code, 0, repaired.stdout + repaired.stderr);
    assert.equal(received.length, before); assert.equal(await readFile(`${strictDir}/injection_exploit_collector.json`, 'utf8'), originalCollector);
    const corrected = JSON.parse(await readFile(`${destination}/report.json`, 'utf8'));
    assert.equal(corrected.findings.length, 1);
    assert.match(JSON.stringify(corrected.findings[0].additional_sections), /POST \/create HTTP/);
    assert.notEqual((await run(process.execPath, args)).code, 0);
    assert.equal(received.length, before);
  });
  console.log(`Verified ${results.length} HTTP evidence/replay scenarios. Artifacts: ${temporary}`);
  await writeFile(`${temporary}/checks.json`, JSON.stringify(results, null, 2));
} finally {
  await new Promise((resolve) => server.close(resolve));
}
