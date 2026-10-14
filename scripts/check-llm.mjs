#!/usr/bin/env node
// Run from any directory: node scripts/check-llm.mjs [chat|stream|tools|all]
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'apps/cli/package.json'));
require('dotenv').config({ path: path.join(root, '.env'), quiet: true });
const spec = process.env.SHANNON_AI_MODEL;
const apiKey = process.env.SHANNON_AI_API_KEY;
const mode = process.argv[2] ?? 'all';
if (!['chat', 'stream', 'tools', 'all'].includes(mode)) {
  throw new Error('Usage: node scripts/check-llm.mjs [chat|stream|tools|all]');
}
if (!spec?.includes(':') || !apiKey) {
  throw new Error('Set SHANNON_AI_MODEL and SHANNON_AI_API_KEY in .env or the environment.');
}
const colon = spec.indexOf(':');
const providerId = spec.slice(0, colon);
const modelId = spec.slice(colon + 1);
const configPath = process.env.LLM_MODELS_CONFIG ?? path.join(root, 'models.volcengine.json');
const provider = JSON.parse(fs.readFileSync(configPath, 'utf8')).providers[providerId];
const model = provider?.models?.find(item => item.id === modelId);
const baseUrl = process.env.SHANNON_AI_BASE_URL ?? provider?.baseUrl;
if (!baseUrl || !model) throw new Error('The selected model is missing from the model configuration.');
const endpoint = `${baseUrl.replace(/\/+$/, '')}/chat/completions`;
const maxTokens = Number(process.env.LLM_MAX_TOKENS ?? model.maxTokens ?? 128);
if (!Number.isSafeInteger(maxTokens) || maxTokens <= 0) throw new Error('LLM_MAX_TOKENS must be a positive integer.');
const tokenField = model.compat?.maxTokensField ?? 'max_tokens';
const clean = value => String(value).split(apiKey).join('[REDACTED]');

async function call(label, body) {
  const started = Date.now();
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: modelId, [tokenField]: maxTokens, ...body }),
    signal: AbortSignal.timeout(90_000),
  });
  const requestId = response.headers.get('x-request-id') ?? response.headers.get('x-tt-logid');
  console.log(`[${label}] HTTP ${response.status}${requestId ? ` request-id=${requestId}` : ''}`);
  if (!response.ok) throw new Error(await response.text());
  let result;
  if (!body.stream) {
    result = await response.json();
    if (result.error) throw new Error(JSON.stringify(result.error));
  } else {
    let buffer = '';
    let text = '';
    let finished = false;
    let usage;
    const decoder = new TextDecoder();
    for await (const chunk of response.body) {
      buffer += decoder.decode(chunk, { stream: true });
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline).trimEnd();
        buffer = buffer.slice(newline + 1);
        if (!line.startsWith('data:')) continue;
        const data = line.slice(5).trim();
        if (data === '[DONE]') { finished = true; continue; }
        if (!data) continue;
        const event = JSON.parse(data);
        if (event.error) throw new Error(JSON.stringify(event.error));
        text += event.choices?.[0]?.delta?.content ?? '';
        usage = event.usage ?? usage;
      }
    }
    if (!finished) throw new Error('The stream ended without a [DONE] event.');
    result = { choices: [{ message: { content: text } }], usage };
  }
  console.log(`[${label}] ${Date.now() - started}ms response=${JSON.stringify(clean(result.choices?.[0]?.message?.content ?? ''))}`);
  if (result.usage) console.log(`[${label}] usage=${JSON.stringify(result.usage)}`);
  return result;
}

const simple = [{ role: 'user', content: 'Reply with exactly: OK' }];
const checks = {
  chat: () => call('chat', { messages: simple, stream: false }),
  stream: () => call('stream', {
    messages: simple,
    stream: true,
    ...(model.compat?.supportsUsageInStreaming && { stream_options: { include_usage: true } }),
  }),
  tools: async () => {
    const messages = [{ role: 'user', content: 'Call test_echo with message="OK", then return its result.' }];
    const tools = [{ type: 'function', function: {
      name: 'test_echo', description: 'Echo a message.',
      parameters: { type: 'object', properties: { message: { type: 'string' } }, required: ['message'] },
    } }];
    const result = await call('tools', { messages, tools, tool_choice: { type: 'function', function: { name: 'test_echo' } } });
    const message = result.choices?.[0]?.message;
    const calls = message?.tool_calls;
    if (!calls?.length) throw new Error('The model did not return a tool call.');
    const replies = calls.map(item => {
      if (item.function?.name !== 'test_echo') throw new Error('Unexpected tool name.');
      const args = JSON.parse(item.function.arguments);
      if (typeof args.message !== 'string') throw new Error('Invalid tool arguments.');
      console.log(`[tools] test_echo(${JSON.stringify(clean(args.message))})`);
      return { role: 'tool', tool_call_id: item.id, content: args.message };
    });
    await new Promise(resolve => setTimeout(resolve, 2000));
    return call('tool-result', {
      messages: [...messages, { role: 'assistant', content: message.content ?? null, tool_calls: calls }, ...replies],
      tools, tool_choice: 'none',
    });
  },
};

console.log(`Model: ${spec}\nEndpoint: ${endpoint}\nMax output tokens: ${maxTokens}`);
for (const name of mode === 'all' ? Object.keys(checks) : [mode]) {
  try {
    await checks[name]();
    console.log(`[${name}] PASS`);
  } catch (error) {
    console.error(`[${name}] FAIL: ${clean(error.message)}${error.cause?.code ? ` (${error.cause.code})` : ''}`);
    process.exitCode = 1;
  }
  await new Promise(resolve => setTimeout(resolve, 2000));
}
