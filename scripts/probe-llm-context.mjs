#!/usr/bin/env node
// node scripts/probe-llm-context.mjs [context|parallel]
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { ModelRuntime } from '../apps/worker/node_modules/@earendil-works/pi-coding-agent/dist/index.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'apps/cli/package.json'));
require('dotenv').config({ path: path.join(root, '.env'), quiet: true });
const spec = process.env.SHANNON_AI_MODEL;
const key = process.env.SHANNON_AI_API_KEY;
if (!spec?.includes(':') || !key) throw new Error('Missing model or API key.');
const colon = spec.indexOf(':');
const providerId = spec.slice(0, colon);
const modelId = spec.slice(colon + 1);
const credentials = new Map([[providerId, { type: 'api_key', key }]]);
const runtime = await ModelRuntime.create({
  modelsPath: path.join(root, 'models.volcengine.json'),
  refreshOnCreate: false,
  credentials: {
    read: async id => credentials.get(id),
    list: async () => [...credentials].map(([providerId, value]) => ({ providerId, type: value.type })),
    modify: async (id, fn) => { const value = await fn(credentials.get(id)); if (value) credentials.set(id, value); return credentials.get(id); },
    delete: async id => { credentials.delete(id); },
  },
});
const found = runtime.getModel(providerId, modelId);
if (!found) throw new Error('Model not found.');
const model = { ...found, ...(process.env.SHANNON_AI_BASE_URL && { baseUrl: process.env.SHANNON_AI_BASE_URL }) };
const mode = process.argv[2] ?? 'context';
const results = [];
const clean = text => String(text ?? '').split(key).join('[REDACTED]');
async function probe(label, units) {
  const prompt = `Ignore the padding below and reply with exactly OK.\n<padding>\n${'x '.repeat(units)}\n</padding>\nReply with exactly OK.`;
  const started = Date.now();
  let httpStatus;
  let requestId;
  try {
    const result = await runtime.completeSimple(model, {
      messages: [{ role: 'user', content: prompt, timestamp: Date.now() }],
    }, {
      maxTokens: model.maxTokens,
      maxRetries: 0,
      timeoutMs: 90_000,
      signal: AbortSignal.timeout(90_000),
      onResponse: response => { httpStatus = response.status; requestId = response.headers['x-request-id'] ?? response.headers['x-tt-logid']; },
    });
    const record = {
      label, units, inputChars: prompt.length, httpStatus, requestId,
      durationMs: Date.now() - started,
      stopReason: result.stopReason,
      inputTokens: result.usage?.input,
      cachedTokens: result.usage?.cacheRead,
      outputTokens: result.usage?.output,
      error: result.errorMessage ? clean(result.errorMessage) : undefined,
      errorLength: result.errorMessage?.length,
      text: clean(result.content.filter(block => block.type === 'text').map(block => block.text).join('')).slice(0, 200),
    };
    results.push(record);
    console.log(JSON.stringify(record));
    return record;
  } catch (error) {
    const record = { label, units, httpStatus, durationMs: Date.now() - started, error: clean(error.message), code: error.cause?.code };
    results.push(record); console.log(JSON.stringify(record)); return record;
  }
}
console.log(JSON.stringify({ model: spec, configuredContextWindow: model.contextWindow, maxOutputTokens: model.maxTokens, mode }));
if (mode === 'context') {
  for (const units of [1024, 32768, 65536, 98304, 122880]) {
    const result = await probe(`context-${units}`, units);
    if (result.error) break;
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
} else if (mode === 'parallel') {
  await Promise.all([1, 2, 3].map(index => probe(`parallel-${index}`, 32768)));
} else throw new Error('Usage: node scripts/probe-llm-context.mjs [context|parallel]');
fs.mkdirSync(path.join(root, 'workspaces', 'llm-diagnostics'), { recursive: true });
const output = path.join(root, 'workspaces', 'llm-diagnostics', `${mode}-${Date.now()}.json`);
fs.writeFileSync(output, JSON.stringify({ model: spec, results }, null, 2), { mode: 0o600 });
console.log(`Report: ${output}`);
if (results.some(result => result.error)) process.exitCode = 1;
