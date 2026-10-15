// Focused integration regression checks. All HTTP requests go to a temporary loopback server.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, readdir, writeFile, symlink, stat } from 'node:fs/promises';
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
const { verifyHttpReplay, replayPlanDigest, hasVerifiedReplay, containsReplaySecret } = await load('services/http-replay');
const { attachHttpEvidence, configuredCaptureRedactions, renderCapturedHttpEvidence, writeReproductionScript } = await load('services/http-evidence');
const { buildRenumberMap } = await load('services/renumber-core');
const { deepRemapStrings } = await load('services/compaction-core');
const { createExploitCollector } = await load('collectors/exploit-collector');
const { buildAddFindingSchema, createFindingCollector } = await load('collectors/finding-collector');
const { renderReport } = await load('services/report-renderer');
const { adaptReportToTypst } = await load('services/report-json-adapter');
const { surfaceReportOutputs } = await load('services/report-output-surface');

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
  await check('credential checks distinguish literal values from field names and endpoint names', async () => {
    const login = { steps: [{ method: 'POST', url: '${BASE_URL}/admin', body_json: { username: '${USERNAME}', password: '${PASSWORD}' }, expect: { status: 200, body_contains: 'private record' } }] };
    assert.equal(containsReplaySecret(login, ['admin', 'password', 'a']), false);
    login.steps[0].body_json.password = 'password';
    assert.equal(containsReplaySecret(login, ['password']), true);
  });
  let proof;
  await check('HTTP 401, wrong impact text, missing assertions and missing variables all fail', async () => {
    assert.ok((await verify('AUTH-01', plan, { BEARER_TOKEN: 'bad' })).error);
    const wrong = structuredClone(plan); wrong.steps[0].expect.body_contains = 'absent-impact';
    assert.ok((await verify('AUTH-02', wrong, { BEARER_TOKEN: 'good' })).error);
    assert.ok((await verify('AUTH-03', { steps: [{ method: 'GET', url: '${BASE_URL}/hex' }] })).error);
    assert.ok((await verify('AUTH-04', plan)).error);
  });
  await check('verified plan records actual HTTP captures and checked assertions', async () => {
    const result = await verify('INJ-02', plan, { BEARER_TOKEN: 'good' });
    assert.ok(result.verification, result.error); proof = result.verification;
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

  const exploit = { status: 'exploited', vulnerability_id: 'INJ-02', title: 'Private endpoint access', vulnerable_location: '/protected', overview: 'Fixture', severity: 'high', severity_rationale: 'Fixture', impact: 'Reads private record', exploitation_steps: ['Read record'], proof_of_impact: 'private-audit-record', http_replay: plan };
  await check('collector rejects unverified/changed plans and accepts only its own execution receipt', async () => {
    const collector = createExploitCollector({ vulnClass: 'injection', validIds: new Set(['INJ-02']), deliverablesDir: dir, targetUrl: target });
    const add = collector.tools.find((tool) => tool.name === 'add_exploit');
    const verifier = collector.tools.find((tool) => tool.name === 'verify_http_replay');
    const status = (result) => JSON.parse(result.content[0].text).status;
    assert.equal(status(await add.execute('one', exploit)), 'error');
    assert.equal(status(await verifier.execute('verify', { vulnerability_id: 'INJ-02', plan, variables: { BEARER_TOKEN: 'good' } })), 'success');
    const changed = structuredClone(exploit); changed.http_replay.steps[0].expect.body_contains = 'different';
    assert.equal(status(await add.execute('changed', changed)), 'error');
    assert.equal(status(await add.execute('valid', exploit)), 'success');
    assert.ok(hasVerifiedReplay(collector.getAll()[0]));
  });
  const renumbered = buildRenumberMap([{ ...exploit, http_replay_verification: proof, reproduction_script: '# capture_curl INJ-02\ntrue' }], 'injection');
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
  await commit({ 'injection_renumber_map.json': { map: { 'INJ-02': 'INJ-01' } }, 'injection_exploit_collector_renumbered.json': renumbered.renumbered });
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
    assert.match(JSON.stringify(findings), /已通过宿主执行/);
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
  await check('missing HTTP captures are disclosed without restoring legacy narrative evidence', async () => {
    const finding = { ...findings[0], additional_sections: [{ heading: 'Proof of Impact', items: [{ kind: 'prose', text: 'Legacy evidence section' }] }, { heading: '验证证据', items: [{ kind: 'prose', text: 'Legacy alternate section' }] }] };
    const report = { report_meta: { target, assessment_date: '2026-10-14', scope: 'Fixture', executive_summary: 'Fixture' }, findings: [finding] };
    const markdown = renderReport(report);
    assert.match(markdown, /此漏洞没有已关联的 HTTP 请求与响应捕获记录/);
    assert.doesNotMatch(markdown, /Proof of Impact|验证证据|Model evidence fragment|Legacy evidence|Legacy alternate/);
    const adapted = adaptReportToTypst(report).findings[0];
    assert.match(adapted.capturedHttpEvidence.items[0].text, /没有已关联/);
    assert.ok(!Object.hasOwn(adapted, 'proofOfImpact'));
    assert.equal(adapted.additionalSections, undefined);
  });
  await check('report credential projection preserves JSON keys, endpoint paths, and session cookies', async () => {
    await capture('AUTH-07', ['-sS', '-H', 'Content-Type: application/json', '-H', 'Cookie: session=admin', '--data-binary', JSON.stringify({ username: 'admin', password: 'password' }), `${target}/login`]);
    await commit({ 'auth_renumber_map.json': { map: { 'AUTH-07': 'AUTH-01' } } });
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
  await check('standalone script works, fails on 401, preserves traces, and separates repeat runs', async () => {
    const script = await writeReproductionScript(dir, target, new Set(['INJ-01']));
    const output = `${temporary}/replay-output`;
    const passed = await run('bash', [script], { env: { ...noProxy, BEARER_TOKEN: 'good', OUTPUT_DIR: output } });
    assert.equal(passed.code, 0, passed.stdout + passed.stderr); assert.match(passed.stdout, /INJ-01: passed/);
    const failed = await run('bash', [script], { env: { ...noProxy, BEARER_TOKEN: 'bad', OUTPUT_DIR: output } });
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
  await check('legacy scripts, changed digests, and empty replay sets cannot produce success', async () => {
    const changed = structuredClone(renumbered.renumbered[0]); changed.http_replay.steps[0].url += '?changed';
    assert.equal(hasVerifiedReplay(changed), false);
    await commit({ 'injection_exploit_collector_renumbered.json': [{ status: 'exploited', vulnerability_id: 'INJ-01', reproduction_script: '# capture_curl INJ-01\ntrue' }] });
    const script = await writeReproductionScript(dir, target, new Set(['INJ-01']));
    const result = await run('bash', [script], { env: { OUTPUT_DIR: `${temporary}/empty-replay` } });
    assert.equal(result.code, 1); assert.doesNotMatch(result.stdout, /: passed/);
  });

  const strictDir = `${temporary}/strict-deliverables`;
  await mkdir(strictDir);
  const strictOptions = { vulnClass: 'injection', validIds: new Set(['INJ-02', 'INJ-03']), deliverablesDir: strictDir, targetUrl: target, requireHttpEvidence: true };
  const strictCollector = createExploitCollector(strictOptions);
  const invoke = async (collector, name, input, signal) => JSON.parse((await collector.tools.find((tool) => tool.name === name).execute('fixture-call', input, signal)).content[0].text);
  const actualExploit = { ...exploit }; delete actualExploit.http_replay;
  let actualReceipt;
  await check('validation and capture are one invocation, with no automatic resend', async () => {
    const before = received.filter((request) => request.url === '/create').length;
    const result = await invoke(strictCollector, 'capture_http_request', { vulnerability_id: 'INJ-02', curl_arguments: ['-sS', '-X', 'POST', `${target}/create`] });
    assert.equal(result.status, 'success'); assert.equal(result.complete, true);
    assert.equal(received.filter((request) => request.url === '/create').length - before, 1);
    assert.match(result.stdout, /created fixture record/);
    actualReceipt = result;
    const saved = await readVerifiedHttpEvidence(strictDir, result);
    assert.match(saved.exchanges[0].request, /^POST \/create HTTP/);
    assert.match(saved.exchanges[0].response, /created fixture record/);
  });
  await check('success submissions without actual HTTP evidence are rejected', async () => {
    assert.equal((await invoke(strictCollector, 'add_exploit', actualExploit)).status, 'error');
    assert.equal(strictCollector.getAll().length, 0);
  });
  await check('capture IDs cannot be invented, reused from another collector, or assigned to another finding', async () => {
    const selected = { ...actualExploit, http_evidence_ids: [actualReceipt.capture_id] };
    assert.equal((await invoke(createExploitCollector(strictOptions), 'add_exploit', selected)).status, 'error');
    assert.equal((await invoke(strictCollector, 'add_exploit', { ...selected, vulnerability_id: 'INJ-03' })).status, 'error');
    assert.equal((await invoke(strictCollector, 'add_exploit', { ...selected, http_evidence_ids: ['00000000-0000-0000-0000-000000000000'] })).status, 'error');
    assert.equal((await invoke(strictCollector, 'add_exploit', { ...selected, http_evidence_ids: [actualReceipt.capture_id, actualReceipt.capture_id] })).status, 'error');
  });
  await check('edited trace files cannot be submitted as actual validation evidence', async () => {
    const file = `${strictDir}/${actualReceipt.file}`, original = await readFile(file, 'utf8');
    await writeFile(file, original + ' ');
    const rejected = await invoke(strictCollector, 'add_exploit', { ...actualExploit, http_evidence_ids: [actualReceipt.capture_id] });
    assert.equal(rejected.status, 'error'); assert.match(rejected.message, /modified after capture/);
    await writeFile(file, original);
  });
  await check('listing existing proof is read-only and valid submissions receive host-only receipts', async () => {
    const before = received.length;
    const listed = await invoke(strictCollector, 'list_http_evidence', { vulnerability_id: 'INJ-02' });
    assert.equal(listed.total, 1); assert.equal(received.length, before);
    assert.equal(listed.flows[0].capture_id, actualReceipt.capture_id);
    assert.equal((await invoke(strictCollector, 'add_exploit', { ...actualExploit, http_evidence_ids: [actualReceipt.capture_id], http_evidence_receipts: [{ sha256: 'forged' }] })).status, 'success');
    assert.equal(strictCollector.getAll()[0].http_evidence_receipts[0].sha256, actualReceipt.sha256);
  });
  await check('failed transfers preserve partial records and cannot count as complete evidence', async () => {
    const collector = createExploitCollector(strictOptions);
    const failed = await invoke(collector, 'capture_http_request', { vulnerability_id: 'INJ-02', curl_arguments: ['-sS', '--connect-timeout', '1', 'http://127.0.0.1:1/'] });
    assert.equal(failed.status, 'success'); assert.equal(failed.complete, false); assert.notEqual(failed.exit_code, 0);
    await stat(`${strictDir}/${failed.file}`);
    assert.equal((await invoke(collector, 'add_exploit', { ...actualExploit, http_evidence_ids: [failed.capture_id] })).status, 'error');
  });
  await check('DOM-only proof is explicit, does not send a replacement request, and records its limitation', async () => {
    const collector = createExploitCollector(strictOptions), before = received.length;
    assert.equal((await invoke(collector, 'add_exploit', { ...actualExploit, http_evidence_unavailable_reason: 'Browser DOM execution proved by screenshot; no applicable HTTP response proves JavaScript execution.' })).status, 'success');
    assert.equal(received.length, before);
    assert.deepEqual(collector.getAll()[0].http_evidence_receipts, []);
    assert.equal((await invoke(strictCollector, 'add_exploit', { ...actualExploit, vulnerability_id: 'INJ-03', http_evidence_unavailable_reason: 'Browser DOM-only proof; see the original screenshot.' })).status, 'success');
    assert.equal((await invoke(createExploitCollector(strictOptions), 'add_exploit', { ...actualExploit, http_evidence_unavailable_reason: '  ' })).status, 'error');
  });
  await check('capture argv stays literal and cannot disable tracing using config, --, or --trace options', async () => {
    const before = received.length;
    for (const args of [['-K', '/tmp/fixture-curlrc'], ['-skK/tmp/fixture-curlrc'], ['--confi=/tmp/fixture-curlrc'], ['--', `${target}/hex`], ['--trace-ascii', '/tmp/trace'], ['curl', `${target}/hex`]]) {
      assert.equal((await invoke(strictCollector, 'capture_http_request', { vulnerability_id: 'INJ-02', curl_arguments: args })).status, 'error');
    }
    assert.equal(received.length, before);
    const result = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sSv', '--get', '--data-urlencode', 'payload=$(echo unwanted);`literal`', `${target}/hex`] });
    const saved = await readVerifiedHttpEvidence(strictDir, result.receipt);
    assert.ok(saved.exchanges[0].request.includes('%24%28echo'));
    assert.equal(result.receipt.complete, true);
    const literal = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', '--data-raw', '--trace-ascii', `${target}/create`] });
    assert.equal(literal.receipt.complete, true);
    assert.equal(received.at(-1).body.toString(), '--trace-ascii');
  });
  await check('timeout keeps the original partial request and does not resend it', async () => {
    const before = received.filter((request) => request.url === '/slow').length;
    const timed = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', `${target}/slow`], timeoutSeconds: 1 });
    assert.equal(timed.receipt.complete, false); assert.equal(timed.receipt.exit_code, 124);
    const saved = await readVerifiedHttpEvidence(strictDir, timed.receipt);
    assert.match(saved.exchanges[0].request, /GET \/slow HTTP/);
    assert.equal(received.filter((request) => request.url === '/slow').length - before, 1);
  });
  await check('cancelled validation sends nothing and preserves large/binary response evidence', async () => {
    const controller = new AbortController(); controller.abort();
    const before = received.length;
    assert.equal((await invoke(strictCollector, 'capture_http_request', { vulnerability_id: 'INJ-03', curl_arguments: ['-sS', `${target}/hex`] }, controller.signal)).status, 'error');
    assert.equal(received.length, before);
    const captured = await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-03', curlArguments: ['-sS', `${target}/large`] });
    assert.match(captured.stdout, /Tool output truncated/);
    const saved = await readVerifiedHttpEvidence(strictDir, captured.receipt);
    const raw = Buffer.from(saved.exchanges[0].response_base64, 'base64');
    assert.deepEqual(raw.subarray(raw.indexOf('\r\n\r\n') + 4), Buffer.alloc(70000, 'Z'));
  });
  let strictRenumbered;
  await check('renumbering preserves original capture identity and file checksums', async () => {
    strictRenumbered = buildRenumberMap(strictCollector.getAll(), 'injection');
    assert.equal(strictRenumbered.renumbered[0].vulnerability_id, 'INJ-01');
    assert.deepEqual(strictRenumbered.renumbered[0].http_evidence_receipts, strictCollector.getAll()[0].http_evidence_receipts);
    assert.equal(strictRenumbered.renumbered[0].http_evidence_receipts[0].finding_id, 'INJ-02');
  });
  await check('report attaches only selected original captures and rejects later evidence modifications', async () => {
    await captureHttpRequest({ deliverablesDir: strictDir, findingId: 'INJ-02', curlArguments: ['-sS', `${target}/binary`] });
    for (const [name, data] of Object.entries({ injection_exploit_collector: strictCollector.getAll(), injection_exploit_collector_renumbered: strictRenumbered.renumbered, injection_renumber_map: { map: Object.fromEntries(strictRenumbered.oldToNew) } })) {
      await writeFile(`${strictDir}/${name}.json`, JSON.stringify(data));
    }
    for (const args of [['init'], ['add', '--', 'injection_exploit_collector.json', 'injection_exploit_collector_renumbered.json', 'injection_renumber_map.json'], ['commit', '-m', 'Actual proof fixture']]) {
      const result = await run('git', args, { cwd: strictDir, env: gitEnv }); assert.equal(result.code, 0, result.stderr);
    }
    const input = [{ ...findings[0], finding_id: 'INJ-01' }, { ...findings[0], finding_id: 'INJ-02' }];
    const report = await attachHttpEvidence(input, strictDir);
    const section = report[0].additional_sections.find((section) => section.heading === '捕获的 HTTP 请求与响应');
    assert.match(JSON.stringify(section), /POST \/create HTTP/);
    assert.match(JSON.stringify(section), new RegExp(actualReceipt.capture_id));
    assert.doesNotMatch(JSON.stringify(section), /GET \/binary HTTP/);
    assert.match(JSON.stringify(report[1]), /Browser DOM-only proof/);
    assert.ok(!report[1].additional_sections.some((section) => section.heading === '捕获的 HTTP 请求与响应'));
    const file = `${strictDir}/${actualReceipt.file}`, original = await readFile(file, 'utf8');
    await writeFile(file, original + ' ');
    await assert.rejects(attachHttpEvidence(input, strictDir), /modified after capture/);
    await writeFile(file, original);
  });
  await check('verified replay captures can satisfy the same host evidence requirement', async () => {
    const collector = createExploitCollector(strictOptions);
    const verified = await invoke(collector, 'verify_http_replay', { vulnerability_id: 'INJ-02', plan, variables: { BEARER_TOKEN: 'good' } });
    assert.equal(verified.status, 'success'); assert.equal(verified.http_evidence.length, 1);
    assert.equal((await invoke(collector, 'add_exploit', { ...exploit, http_evidence_ids: verified.http_evidence.map((receipt) => receipt.capture_id) })).status, 'success');
  });
  console.log(`Verified ${results.length} HTTP evidence/replay scenarios. Artifacts: ${temporary}`);
  await writeFile(`${temporary}/checks.json`, JSON.stringify(results, null, 2));
} finally {
  await new Promise((resolve) => server.close(resolve));
}
