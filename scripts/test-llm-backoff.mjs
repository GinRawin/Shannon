import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ModelRuntime, DefaultResourceLoader } from '../apps/worker/node_modules/@earendil-works/pi-coding-agent/dist/index.js';
import { createAssistantMessageEventStream } from '../apps/worker/node_modules/@earendil-works/pi-ai/dist/utils/event-stream.js';
import { applyLlmRequestRateLimit, configureLlmRequestRateLimit, Llm429Backoff } from '../apps/worker/dist/ai/request-rate-limiter.js';
import { classifyProviderFailure } from '../apps/worker/dist/services/error-handling.js';
import { createTaskTool } from '../apps/worker/dist/ai/pi/task-tool.js';
import { runPiPrompt } from '../apps/worker/dist/ai/pi/pi-executor.js';
import { safeExecutionFailureDetails } from '../apps/worker/dist/ai/pi/turn-error.js';

const body = { code: 'ModelAccountTpmRateLimitExceeded', message: 'TPM limit exceeded', type: 'TooManyRequests' };
const errorText = `429: ${JSON.stringify(body)}`;
const flush = async () => { for (let i = 0; i < 100; i++) await new Promise(setImmediate); };
async function runtimeFixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shannon-backoff-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = path.join(dir, 'models.json');
  fs.writeFileSync(config, JSON.stringify({ providers: { fixture: { baseUrl: 'https://fixture.invalid/v1', api: 'openai-completions', models: [{ id: 'fixture-model', name: 'Fixture', reasoning: false, input: ['text'], contextWindow: 128000, maxTokens: 128, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, compat: { supportsStore: false, supportsDeveloperRole: false, supportsReasoningEffort: false, supportsStrictMode: false, maxTokensField: 'max_tokens' } }] } } }));
  const runtime = await ModelRuntime.create({ modelsPath: config, refreshOnCreate: false, credentials: { read: async () => ({ type: 'api_key', key: 'test' }), list: async () => [{ providerId: 'fixture', type: 'api_key' }], modify: async (_, fn) => fn({ type: 'api_key', key: 'test' }), delete: async () => {} } });
  return { runtime, model: runtime.getModel('fixture', 'fixture-model'), dir };
}

test('TPM JSON is transient; quota exhaustion remains terminal', () => {
  assert.equal(classifyProviderFailure({ stopReason: 'error', errorMessage: errorText }).category, 'rate_limit');
  assert.equal(classifyProviderFailure({ stopReason: 'error', errorMessage: errorText }).retryable, true);
  assert.equal(classifyProviderFailure({ stopReason: 'error', errorMessage: '429: {"code":"insufficient_quota"}' }).retryable, false);
});

test('TPM cooldown doubles, honors Retry-After, and ignores stale successes', async t => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 0 });
  t.mock.method(console, 'warn', () => {});
  const backoff = new Llm429Backoff();
  backoff.observe(Response.json(body, { status: 429 }), 0, true);
  backoff.observe(new Response('', { status: 200 }), 0);
  let ready = false;
  const first = backoff.wait().then(() => { ready = true; });
  t.mock.timers.tick(59_999); await flush(); assert.equal(ready, false);
  t.mock.timers.tick(1); await first;
  backoff.observe(Response.json(body, { status: 429 }), 1, true);
  ready = false;
  const second = backoff.wait().then(() => { ready = true; });
  t.mock.timers.tick(119_999); await flush(); assert.equal(ready, false);
  t.mock.timers.tick(1); await second;
  const headers = new Headers({ 'retry-after': '240' });
  backoff.observe(new Response('', { status: 429, headers }), 2);
  ready = false;
  const third = backoff.wait().then(() => { ready = true; });
  t.mock.timers.tick(239_999); await flush(); assert.equal(ready, false);
  t.mock.timers.tick(1); await third;
});

test('real Pi SDK retries HTTP 429 and gateway TPM errors after 60s and 120s', async t => {
  const { runtime, model } = await runtimeFixture(t);
  configureLlmRequestRateLimit(undefined);
  applyLlmRequestRateLimit(runtime);
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: 0 });
  t.mock.method(console, 'warn', () => {});
  const starts = [];
  const fetch = async () => {
    starts.push(Date.now());
    if (starts.length <= 2) return Response.json({ error: body }, { status: starts.length === 1 ? 429 : 400 });
    const chunk = { id: 'fixture-response', choices: [{ index: 0, delta: { role: 'assistant', content: 'OK' }, finish_reason: 'stop' }], usage: { prompt_tokens: 10, completion_tokens: 1, total_tokens: 11 } };
    return new Response(`data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`, { headers: { 'content-type': 'text/event-stream' } });
  };
  const pending = runtime.completeSimple(model, { messages: [{ role: 'user', content: 'Say OK', timestamp: 0 }] }, { fetch, maxRetries: 2, timeoutMs: 1_000_000 });
  await flush(); assert.equal(starts.length, 1);
  t.mock.timers.tick(60_000); await flush(); assert.equal(starts.length, 2);
  t.mock.timers.tick(120_000); await flush();
  const result = await pending;
  assert.deepEqual(starts, [0, 60_000, 180_000]);
  assert.equal(result.stopReason, 'stop');
  assert.equal(result.content.find(block => block.type === 'text').text, 'OK');
});

test('exhausted child TPM failure is propagated to its parent', async t => {
  const { runtime, model, dir } = await runtimeFixture(t);
  const oldDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = dir;
  t.after(() => { if (oldDir === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = oldDir; });
  t.mock.method(console, 'warn', () => {});
  runtime.streamSimple = () => {
    const stream = createAssistantMessageEventStream();
    const error = { role: 'assistant', content: [], provider: model.provider, api: model.api, model: model.id, stopReason: 'error', errorMessage: errorText, timestamp: Date.now(), usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
    stream.push({ type: 'error', reason: 'error', error }); return stream;
  };
  let parentFailure;
  const tool = createTaskTool({ cwd: dir, model, modelRuntime: runtime, parentAgentName: 'pre-recon', onFailure: error => { parentFailure = error; }, createResourceLoader: async () => { const loader = new DefaultResourceLoader({ cwd: dir, agentDir: dir, noExtensions: true, noSkills: true }); await loader.reload(); return loader; } });
  const result = await tool.execute('fixture-task', { prompt: 'Analyze source.' });
  assert.equal(parentFailure.retryable, true);
  assert.equal(parentFailure.providerCategory, 'rate_limit');
  assert.match(result.content[0].text, /rate_limit/);
});

function setEnv(t, key, value) {
  const previous = process.env[key];
  if (value === undefined) delete process.env[key]; else process.env[key] = value;
  t.after(() => { if (previous === undefined) delete process.env[key]; else process.env[key] = previous; });
}

function response(model, { text, tool, error } = {}) {
  const stream = createAssistantMessageEventStream();
  const message = {
    role: 'assistant', provider: model.provider, api: model.api, model: model.id,
    content: tool ? [{ type: 'toolCall', ...tool }] : text ? [{ type: 'text', text }] : [],
    stopReason: error ? 'error' : tool ? 'toolUse' : 'stop', timestamp: Date.now(),
    ...(error ? { errorMessage: error } : {}),
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
  };
  stream.push(error ? { type: 'error', reason: 'error', error: message } : { type: 'done', reason: message.stopReason, message });
  return stream;
}

async function recoveryFixture(t) {
  const fixture = await runtimeFixture(t);
  setEnv(t, 'PI_CODING_AGENT_DIR', fixture.dir);
  setEnv(t, 'SHANNON_AI_MODEL', 'fixture:fixture-model');
  setEnv(t, 'SHANNON_AI_BASE_URL', undefined);
  setEnv(t, 'SHANNON_DELIVERABLES_DIR', path.join(fixture.dir, '.shannon', 'deliverables'));
  fs.mkdirSync(process.env.SHANNON_DELIVERABLES_DIR, { recursive: true });
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'log', () => {});
  return fixture;
}

for (const mode of ['retry', 'unresolved', 'unrelated', 'failed-retry', 'parent-error']) {
  test(`parent completion after a child failure: ${mode}`, async t => {
    const { runtime, model, dir } = await recoveryFixture(t);
    t.mock.method(ModelRuntime, 'create', async () => runtime);
    let parentTurns = 0;
    let childTurns = 0;
    runtime.streamSimple = (_model, context) => {
      const user = context.messages.find(message => message.role === 'user');
      const text = typeof user.content === 'string' ? user.content : user.content.map(block => block.text ?? '').join('');
      if (text.includes('CHILD_TEST')) {
        childTurns++;
        return response(model, childTurns === 1 || mode === 'failed-retry' ? { error: errorText } : { text: 'Source investigation complete.' });
      }
      parentTurns++;
      if (parentTurns === 1) return response(model, { tool: { id: 'initial-task', name: 'task', arguments: { prompt: 'CHILD_TEST', description: 'Audit frontend' } } });
      if (parentTurns === 2 && mode !== 'unresolved') {
        return response(model, { tool: { id: 'replacement-task', name: 'task', arguments: { prompt: 'CHILD_TEST', description: 'Narrow audit retry', ...(mode === 'unrelated' ? {} : { retry_of: 'initial-task' }) } } });
      }
      return response(model, mode === 'parent-error' ? { error: 'provider failed after child recovered' } : { text: 'All required investigation complete.' });
    };
    const logger = { info() {}, warn() {}, error() {} };
    const result = await runPiPrompt('PARENT_TEST', dir, '', 'test', null, null, logger);
    assert.equal(result.success, mode === 'retry');
    assert.equal(childTurns, mode === 'unresolved' ? 1 : 2);
    if (mode === 'retry') assert.equal(result.result, 'All required investigation complete.');
    else assert.equal(result.errorType, 'AGENT_EXECUTION_FAILED');
  });
}

test('a successful retry chain resolves only the related failures', async t => {
  const { runtime, model, dir } = await recoveryFixture(t);
  const pending = new Set();
  let call = 0;
  runtime.streamSimple = () => response(model, ++call <= 3 ? { error: errorText } : { text: 'Recovered.' });
  const tool = createTaskTool({
    cwd: dir, model, modelRuntime: runtime, parentAgentName: 'record',
    onFailure: error => pending.add(error), onRecovery: error => pending.delete(error),
    createResourceLoader: async () => {
      const loader = new DefaultResourceLoader({ cwd: dir, agentDir: dir, noExtensions: true, noSkills: true });
      await loader.reload(); return loader;
    },
  });
  await tool.execute('a', { prompt: 'Audit', description: 'Audit frontend' });
  await tool.execute('b', { prompt: 'Other', description: 'Other frontend' });
  await tool.execute('c', { prompt: 'Audit retry', description: 'Audit retry', retry_of: 'a' });
  assert.equal(pending.size, 3);
  await tool.execute('d', { prompt: 'Audit retry again', retry_of: 'c' });
  assert.equal(pending.size, 1, 'independent failed work must still fail the parent');
  const invalid = await tool.execute('e', { prompt: 'Invalid', retry_of: 'already recovered' });
  assert.match(invalid.content[0].text, /Invalid retry_of/);
  assert.equal(call, 4, 'an invalid retry must not execute a model request');
});

test('child setup exceptions persist bounded opt-in diagnostics and support recovery', async t => {
  const { runtime, model, dir } = await recoveryFixture(t);
  setEnv(t, 'SHANNON_DEBUG_PROVIDER_ERRORS', '1');
  let setupAttempts = 0;
  const pending = new Set();
  const tool = createTaskTool({
    cwd: dir, model, modelRuntime: runtime, parentAgentName: 'record',
    onFailure: error => pending.add(error), onRecovery: error => pending.delete(error),
    createResourceLoader: async () => {
      if (++setupAttempts === 1) throw new TypeError('fixture setup failed\n' + 'x'.repeat(800));
      const loader = new DefaultResourceLoader({ cwd: dir, agentDir: dir, noExtensions: true, noSkills: true });
      await loader.reload(); return loader;
    },
  });
  const result = await tool.execute('setup', { prompt: 'Analyze', description: 'Audit setup' });
  assert.match(result.content[0].text, /Task ID: setup/);
  const log = JSON.parse(fs.readFileSync(path.join(process.env.SHANNON_DELIVERABLES_DIR, 'error.log'), 'utf8'));
  assert.equal(log.stage, 'create-session');
  assert.equal(log.execution.errorName, 'TypeError');
  assert.equal(log.execution.errorMessageLength, 821);
  assert.ok(log.execution.errorMessageSnippet.length <= 500);
  assert.ok(!log.execution.errorMessageSnippet.includes('\n'));
  runtime.streamSimple = () => response(model, { text: 'Recovered setup.' });
  await tool.execute('setup-retry', { prompt: 'Analyze', retry_of: 'setup' });
  assert.equal(pending.size, 0);
});

test('execution diagnostics omit error prose unless debugging is enabled', t => {
  setEnv(t, 'SHANNON_DEBUG_PROVIDER_ERRORS', undefined);
  const error = Object.assign(new Error('private diagnostic text'), { code: 'ECONNRESET' });
  const details = safeExecutionFailureDetails(error);
  assert.equal(details.errorName, 'Error');
  assert.equal(details.errorCode, 'ECONNRESET');
  assert.equal(details.errorMessageLength, 23);
  assert.equal(details.errorMessageSnippet, undefined);
  setEnv(t, 'SHANNON_DEBUG_PROVIDER_ERRORS', 'true');
  assert.equal(safeExecutionFailureDetails(error).errorMessageSnippet, 'private diagnostic text');
});
