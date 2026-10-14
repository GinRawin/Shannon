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
