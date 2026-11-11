#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const STATE_SCHEMA_VERSION = 1;
const DEFAULT_SHANNON = fileURLToPath(new URL('../shannon', import.meta.url));
const MODELS_CONFIG = process.env.SHANNON_MODELS_CONFIG ?? fileURLToPath(new URL('../models.volcengine.json', import.meta.url));
const FINAL_STATUSES = new Set(['completed', 'failed']);

function usage() {
  console.log(`Usage:
  ./scripts/batch-start.mjs <queue-file> [options] -- [shared shannon start options]

Accepted queue formats:
  JSONL: {"web_url":"https://app.example.com","code_location":"/path/to/repo"}
  Array: [{"web_url":"https://app.example.com","code_location":"/path/to/repo"}]

Options:
  --state <path>         State file (default: <queue>.shannon-batch-state.json)
  --shannon <path>       Shannon executable (default: repository ./shannon)

  SHANNON_MODELS_CONFIG  Override the models config (default: repository models.volcengine.json)
  --stop-on-error        Stop after the first failed scan (default: continue)
  --retry-failed         Retry records already marked failed once in this run
  --watch                Wait for newly written records after the queue is drained
  --poll-seconds <n>     Watch interval in seconds (default: 30)
  -h, --help             Show this help

Records are processed in file order. The queue is re-read after every scan and
is never modified. Each scan automatically uses:
  -c <code_location>/config.yaml
  --models-config ${MODELS_CONFIG}
  --follow

Do not pass -u/--url, -r/--repo, -c/--config, --models-config, or
-w/--workspace after --.`);
}

function fail(message) {
  console.error(`[batch] ${message}`);
  process.exitCode = 1;
}

function readOptionValue(args, index, name) {
  const value = args[index + 1];
  if (!value || value.startsWith('-')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function parseArgs(argv) {
  const separatorIndex = argv.indexOf('--');
  const runnerArgs = separatorIndex === -1 ? argv : argv.slice(0, separatorIndex);
  const startArgs = separatorIndex === -1 ? [] : argv.slice(separatorIndex + 1);

  let queuePath;
  let statePath;
  let shannonPath = DEFAULT_SHANNON;
  let stopOnError = false;
  let retryFailed = false;
  let watch = false;
  let pollSeconds = 30;

  for (let index = 0; index < runnerArgs.length; index += 1) {
    const arg = runnerArgs[index];
    if (arg === '-h' || arg === '--help') {
      usage();
      process.exit(0);
    }
    if (arg === '--state') {
      statePath = readOptionValue(runnerArgs, index, '--state');
      index += 1;
      continue;
    }
    if (arg === '--shannon') {
      shannonPath = readOptionValue(runnerArgs, index, '--shannon');
      index += 1;
      continue;
    }
    if (arg === '--stop-on-error') {
      stopOnError = true;
      continue;
    }
    if (arg === '--retry-failed') {
      retryFailed = true;
      continue;
    }
    if (arg === '--watch') {
      watch = true;
      continue;
    }
    if (arg === '--poll-seconds') {
      const value = Number(readOptionValue(runnerArgs, index, '--poll-seconds'));
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error('--poll-seconds must be a positive number');
      }
      pollSeconds = value;
      index += 1;
      continue;
    }
    if (arg.startsWith('-')) {
      throw new Error(`unknown batch option: ${arg}`);
    }
    if (queuePath) {
      throw new Error('only one queue file may be supplied');
    }
    queuePath = arg;
  }

  if (!queuePath) {
    throw new Error('a queue file is required');
  }

  const forbiddenStartArgs = [
    ['-u', '--url'],
    ['-r', '--repo'],
    ['-c', '--config'],
    ['--models-config'],
    ['-w', '--workspace'],
  ];
  for (const aliases of forbiddenStartArgs) {
    const found = startArgs.some(
      (arg) => aliases.includes(arg) || aliases.some((alias) => alias.startsWith('--') && arg.startsWith(`${alias}=`)),
    );
    if (found) {
      throw new Error(`${aliases.join('/')} is managed by the batch runner and must not be passed after --`);
    }
  }

  const resolvedQueuePath = path.resolve(queuePath);
  return {
    queuePath: resolvedQueuePath,
    statePath: path.resolve(statePath ?? `${resolvedQueuePath}.shannon-batch-state.json`),
    shannonPath: path.resolve(shannonPath),
    startArgs,
    stopOnError,
    retryFailed,
    watch,
    pollSeconds,
  };
}

function stripTrailingCommas(text) {
  let result = '';
  let inString = false;
  let escaped = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (inString) {
      result += character;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }

    if (character === '"') {
      inString = true;
      result += character;
      continue;
    }
    if (character === ',') {
      let nextIndex = index + 1;
      while (nextIndex < text.length && /\s/.test(text[nextIndex])) nextIndex += 1;
      if (text[nextIndex] === '}' || text[nextIndex] === ']') continue;
    }
    result += character;
  }

  return result;
}

function validateRecord(value, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${source} must contain a JSON object`);
  }
  if (typeof value.web_url !== 'string' || !value.web_url.trim()) {
    throw new Error(`${source} has no non-empty web_url`);
  }
  if (typeof value.code_location !== 'string' || !value.code_location.trim()) {
    throw new Error(`${source} has no non-empty code_location`);
  }

  return {
    webUrl: value.web_url.trim(),
    codeLocation: value.code_location.trim(),
    source,
  };
}

function addRecordIdentities(records) {
  const occurrences = new Map();
  return records.map((record) => {
    const pair = JSON.stringify([record.webUrl, record.codeLocation]);
    const occurrence = occurrences.get(pair) ?? 0;
    occurrences.set(pair, occurrence + 1);
    const id = createHash('sha256').update(`${pair}\0${occurrence}`).digest('hex');
    return { ...record, id };
  });
}

function parseQueue(queuePath) {
  let text;
  try {
    text = fs.readFileSync(queuePath, 'utf8').replace(/^\uFEFF/, '');
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new Error(`queue file does not exist: ${queuePath}`);
    }
    throw error;
  }

  if (!text.trim()) return [];
  const trimmed = text.trimStart();
  if (trimmed.startsWith('[')) {
    let values;
    try {
      values = JSON.parse(stripTrailingCommas(text));
    } catch (error) {
      throw new Error(`invalid JSON array in ${queuePath}: ${error.message}`);
    }
    if (!Array.isArray(values)) {
      throw new Error(`${queuePath} must contain a JSON array`);
    }
    return addRecordIdentities(values.map((value, index) => validateRecord(value, `array item ${index + 1}`)));
  }

  const records = [];
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    let line = rawLine.trim();
    if (!line) continue;
    if (line.endsWith(',')) line = line.slice(0, -1);
    let value;
    try {
      value = JSON.parse(stripTrailingCommas(line));
    } catch (error) {
      throw new Error(`invalid JSON on line ${index + 1}: ${error.message}`);
    }
    records.push(validateRecord(value, `line ${index + 1}`));
  }
  return addRecordIdentities(records);
}

async function readQueueWithRetry(queuePath) {
  let lastError;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      return parseQueue(queuePath);
    } catch (error) {
      lastError = error;
      if (attempt < 4) await sleep(500);
    }
  }
  throw lastError;
}

function emptyState(queuePath) {
  return {
    schema_version: STATE_SCHEMA_VERSION,
    queue_file: queuePath,
    records: {},
  };
}

function loadState(statePath, queuePath) {
  let state;
  try {
    state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return emptyState(queuePath);
    throw new Error(`could not read state file ${statePath}: ${error.message}`);
  }

  if (
    !state ||
    state.schema_version !== STATE_SCHEMA_VERSION ||
    state.queue_file !== queuePath ||
    !state.records ||
    typeof state.records !== 'object' ||
    Array.isArray(state.records)
  ) {
    throw new Error(`state file is incompatible with this queue: ${statePath}`);
  }
  return state;
}

function writeState(statePath, state) {
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  const temporaryPath = `${statePath}.${process.pid}.${randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
    fs.renameSync(temporaryPath, statePath);
  } finally {
    try {
      fs.unlinkSync(temporaryPath);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
}

async function claimNextRecord(options, attemptedIds) {
  const queue = await readQueueWithRetry(options.queuePath);
  const state = loadState(options.statePath, options.queuePath);
  const next = queue.find((record) => {
    const status = state.records[record.id]?.status;
    if (!status || status === 'pending' || status === 'running') return true;
    return options.retryFailed && status === 'failed' && !attemptedIds.has(record.id);
  });
  if (!next) return null;

  const previous = state.records[next.id];
  state.records[next.id] = {
    web_url: next.webUrl,
    code_location: next.codeLocation,
    source: next.source,
    status: 'running',
    attempts: Number.isSafeInteger(previous?.attempts) ? previous.attempts + 1 : 1,
    started_at: new Date().toISOString(),
  };
  writeState(options.statePath, state);
  return { ...next, resumed: previous?.status === 'running' };
}

function finishRecord(options, job, outcome) {
  const state = loadState(options.statePath, options.queuePath);
  const current = state.records[job.id];
  if (!current || current.status !== 'running') {
    throw new Error(`state for ${job.source} changed while its scan was running`);
  }

  state.records[job.id] = {
    ...current,
    status: outcome.status,
    finished_at: new Date().toISOString(),
    exit_code: outcome.exitCode,
    signal: outcome.signal,
  };
  writeState(options.statePath, state);
}

function shellQuote(value) {
  return /^[A-Za-z0-9_./:@%+=,?#&-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

function runScan(options, job, signalState) {
  const configPath = path.join(job.codeLocation, 'config.yaml');
  if (!fs.existsSync(configPath)) {
    return Promise.resolve({
      exitCode: 1,
      signal: null,
      spawnError: new Error(`project config does not exist: ${configPath}`),
    });
  }

  const hasFollow = options.startArgs.includes('-f') || options.startArgs.includes('--follow');
  const args = [
    'start',
    '-u',
    job.webUrl,
    '-r',
    job.codeLocation,
    '-c',
    configPath,
    '--models-config',
    MODELS_CONFIG,
    ...options.startArgs,
    ...(hasFollow ? [] : ['--follow']),
  ];

  console.log(`\n[batch] ${job.source}: ${job.webUrl}`);
  console.log(`[batch] repo: ${job.codeLocation}`);
  console.log(`[batch] config: ${configPath}`);
  if (job.resumed) console.log('[batch] retrying a record left running by an interrupted runner');
  console.log(`[batch] command: ${[options.shannonPath, ...args].map(shellQuote).join(' ')}`);

  return new Promise((resolve) => {
    const child = spawn(options.shannonPath, args, { stdio: 'inherit' });
    signalState.child = child;
    let settled = false;
    const settle = (outcome) => {
      if (settled) return;
      settled = true;
      signalState.child = null;
      resolve(outcome);
    };

    child.once('error', (error) => settle({ exitCode: 1, signal: null, spawnError: error }));
    child.once('exit', (exitCode, signal) => settle({ exitCode, signal, spawnError: null }));
  });
}

function acquireLock(statePath) {
  const lockPath = `${statePath}.lock`;
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = fs.openSync(lockPath, 'wx');
      fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }));
      return () => {
        fs.closeSync(fd);
        try {
          fs.unlinkSync(lockPath);
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error;
        }
      };
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let owner;
      try {
        owner = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        process.kill(owner.pid, 0);
      } catch (ownerError) {
        if (ownerError?.code === 'EPERM') {
          throw new Error(`another batch runner owns ${lockPath}`);
        }
        fs.unlinkSync(lockPath);
        continue;
      }
      throw new Error(`another batch runner is active with pid ${owner.pid}`);
    }
  }

  throw new Error(`could not acquire batch lock: ${lockPath}`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(MODELS_CONFIG)) {
    throw new Error(`models config does not exist: ${MODELS_CONFIG}`);
  }
  const releaseLock = acquireLock(options.statePath);
  const attemptedIds = new Set();
  const signalState = { child: null, received: null };
  let sawFailure = false;

  const forwardSignal = (signal) => {
    if (signalState.received) return;
    signalState.received = signal;
    console.error(`\n[batch] received ${signal}; stopping the active scan`);
    signalState.child?.kill(signal);
  };
  process.on('SIGINT', () => forwardSignal('SIGINT'));
  process.on('SIGTERM', () => forwardSignal('SIGTERM'));

  try {
    console.log(`[batch] queue: ${options.queuePath}`);
    console.log(`[batch] state: ${options.statePath}`);
    console.log('[batch] order: first unfinished record in file order');

    while (!signalState.received) {
      const job = await claimNextRecord(options, attemptedIds);
      if (!job) {
        if (!options.watch) {
          console.log('[batch] queue drained');
          break;
        }
        console.log(`[batch] queue drained; checking again in ${options.pollSeconds} seconds`);
        await sleep(options.pollSeconds * 1000);
        continue;
      }

      attemptedIds.add(job.id);
      const outcome = await runScan(options, job, signalState);
      if (signalState.received) {
        finishRecord(options, job, {
          status: 'pending',
          exitCode: outcome.exitCode,
          signal: outcome.signal ?? signalState.received,
        });
        break;
      }

      if (outcome.spawnError) {
        console.error(`[batch] failed to launch Shannon: ${outcome.spawnError.message}`);
      }
      const succeeded = outcome.exitCode === 0;
      const status = succeeded ? 'completed' : 'failed';
      if (!FINAL_STATUSES.has(status)) throw new Error(`invalid final status: ${status}`);
      finishRecord(options, job, {
        status,
        exitCode: outcome.exitCode,
        signal: outcome.signal,
      });

      if (succeeded) {
        console.log(`[batch] completed ${job.source}`);
      } else {
        sawFailure = true;
        console.error(
          `[batch] failed ${job.source}${outcome.exitCode !== null ? ` (exit ${outcome.exitCode})` : ''}${outcome.signal ? ` (${outcome.signal})` : ''}`,
        );
        if (options.stopOnError) break;
      }
    }
  } finally {
    releaseLock();
  }

  if (signalState.received) {
    process.exitCode = signalState.received === 'SIGINT' ? 130 : 143;
  } else if (sawFailure) {
    process.exitCode = 1;
  }
}

try {
  await main();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
