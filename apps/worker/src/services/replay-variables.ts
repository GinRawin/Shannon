import { createHmac, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { type BrowserReplayPlan, browserReplayVariableNames } from './browser-replay.js';
import type { HttpReplayPlan } from './http-replay.js';

export type ReplayVariableRefresh = 'each_attempt' | 'on_ttl_expiry';
export type ReplayVariableDefinition =
  | string
  | { value: string; kind?: 'static'; refresh?: ReplayVariableRefresh; ttl_seconds?: number; updated_at?: string }
  | { value: string; kind: 'totp'; refresh?: ReplayVariableRefresh; ttl_seconds?: number; updated_at?: string }
  | {
      kind: 'response_extract';
      source_finding: string;
      pointer: string;
      refresh?: ReplayVariableRefresh;
      ttl_seconds?: number;
      updated_at?: string;
    };

export interface ReplayVariableDiagnostic {
  name: string;
  status: 'resolved' | 'missing' | 'expired' | 'extract_failed' | 'invalid';
  kind: 'static' | 'totp' | 'response_extract';
  message?: string;
}

export interface ReplayVariableResolution {
  values: Record<string, string>;
  diagnostics: ReplayVariableDiagnostic[];
}

export interface ReplayVariableCacheEntry {
  definition: string;
  value: string;
  capturedAt: number;
}

/** Keep the source timestamp with each body so rereading a stale token cannot renew its TTL. */
export async function loadReplayResponses(deliverablesDir: string): Promise<{
  responseBodies: ReadonlyMap<string, unknown>;
  responseCapturedAt: ReadonlyMap<string, number>;
}> {
  const root = path.join(deliverablesDir, 'http-exchanges');
  const responses = new Map<string, unknown>();
  const capturedAt = new Map<string, number>();
  let directories: import('node:fs').Dirent[];
  try {
    directories = await fs.readdir(root, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      return { responseBodies: responses, responseCapturedAt: capturedAt };
    throw error;
  }
  for (const directory of directories) {
    if (!directory.isDirectory() || !validFindingId(directory.name)) continue;
    const files = (await fs.readdir(path.join(root, directory.name)))
      .filter((name) => /^exchange-.*\.json$/.test(name))
      .sort()
      .reverse();
    for (const name of files) {
      try {
        const record = JSON.parse(await fs.readFile(path.join(root, directory.name, name), 'utf8')) as {
          captured_at?: string;
          exit_code?: number;
          errors?: unknown[];
          exchanges?: Array<{ response_base64?: unknown }>;
        };
        if (record.exit_code !== 0 || record.errors?.length) continue;
        const timestamp = Date.parse(record.captured_at ?? '');
        if (!Number.isFinite(timestamp) || timestamp <= (capturedAt.get(directory.name) ?? -Infinity)) continue;
        const encoded = record.exchanges?.at(-1)?.response_base64;
        if (typeof encoded !== 'string') continue;
        const raw = Buffer.from(encoded, 'base64').toString('utf8');
        const separator = raw.indexOf('\r\n\r\n');
        const alternate = raw.indexOf('\n\n');
        const body = raw.slice(separator >= 0 ? separator + 4 : alternate >= 0 ? alternate + 2 : 0);
        responses.set(directory.name, JSON.parse(body) as unknown);
        capturedAt.set(directory.name, timestamp);
      } catch {
        // Try the next newest complete JSON response for this finding.
      }
    }
  }
  return { responseBodies: responses, responseCapturedAt: capturedAt };
}

/** Compatibility projection for callers that only need the parsed bodies. */
export async function loadReplayResponseBodies(deliverablesDir: string): Promise<ReadonlyMap<string, unknown>> {
  return (await loadReplayResponses(deliverablesDir)).responseBodies;
}

function validFindingId(findingId: string): boolean {
  return /^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(findingId);
}

function normalizeDefinitions(data: unknown): Record<string, ReplayVariableDefinition> {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid variable file');
  const values: Record<string, ReplayVariableDefinition> = {};
  for (const [key, value] of Object.entries(data)) {
    const name = key.toUpperCase();
    if (!/^[A-Z][A-Z0-9_]*$/.test(name) || ['BASE_URL', 'XSS_MARKER'].includes(name) || Object.hasOwn(values, name))
      throw new Error('Invalid variable file');
    if (typeof value === 'string') {
      if (value.includes('\0')) throw new Error('Invalid variable file');
      values[name] = value;
      continue;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid variable file');
    const definition = value as Record<string, unknown>;
    const kind = definition.kind ?? 'static';
    if (!['static', 'totp', 'response_extract'].includes(String(kind))) throw new Error('Invalid variable file');
    if (definition.refresh !== undefined && !['each_attempt', 'on_ttl_expiry'].includes(String(definition.refresh)))
      throw new Error('Invalid variable file');
    if (
      definition.ttl_seconds !== undefined &&
      (!Number.isInteger(definition.ttl_seconds) || Number(definition.ttl_seconds) <= 0)
    )
      throw new Error('Invalid variable file');
    if (
      definition.updated_at !== undefined &&
      (typeof definition.updated_at !== 'string' || !Number.isFinite(Date.parse(definition.updated_at)))
    )
      throw new Error('Invalid variable file');
    if (kind === 'response_extract') {
      if (
        !validFindingId(String(definition.source_finding)) ||
        typeof definition.pointer !== 'string' ||
        !definition.pointer
      )
        throw new Error('Invalid variable file');
      values[name] = definition as ReplayVariableDefinition;
    } else {
      if (typeof definition.value !== 'string' || definition.value.includes('\0'))
        throw new Error('Invalid variable file');
      values[name] = definition as ReplayVariableDefinition;
    }
  }
  return values;
}

/** Per-finding secrets stay outside deliverables and source-control checkpoints. */
export async function loadReplayVariableDefinitions(
  directory: string,
  findingId: string,
): Promise<Record<string, ReplayVariableDefinition>> {
  if (!validFindingId(findingId)) throw new Error('Invalid finding ID');
  const file = path.join(directory, `${findingId}.json`);
  try {
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new Error('Invalid variable file');
    await fs.chmod(file, 0o600);
    return normalizeDefinitions(JSON.parse(await fs.readFile(file, 'utf8')) as unknown);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw error;
  }
}

function decodeBase32(value: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = value.toUpperCase().replace(/[\s=-]/g, '');
  if (!normalized || [...normalized].some((character) => !alphabet.includes(character)))
    throw new Error('Invalid TOTP secret');
  let bits = '';
  for (const character of normalized) bits += alphabet.indexOf(character).toString(2).padStart(5, '0');
  const bytes: number[] = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8)
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  return Buffer.from(bytes);
}

export function generateTotp(secret: string, now = Date.now()): string {
  const counter = Math.floor(now / 30_000);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decodeBase32(secret)).update(message).digest();
  const last = digest.at(-1);
  if (last === undefined) throw new Error('TOTP digest is empty');
  const offset = last & 0x0f;
  const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, '0');
}

function extractPointer(value: unknown, pointer: string): unknown {
  const parts = pointer.startsWith('/')
    ? pointer
        .slice(1)
        .split('/')
        .map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
    : pointer.split('.');
  let current = value;
  for (const part of parts.filter(Boolean)) {
    if (Array.isArray(current) && /^\d+$/.test(part)) current = current[Number(part)];
    else if (current && typeof current === 'object') current = (current as Record<string, unknown>)[part];
    else return undefined;
  }
  return current;
}

export function resolveReplayVariables(args: {
  definitions: Record<string, ReplayVariableDefinition>;
  baseUrl: string;
  now?: number;
  responseBodies?: ReadonlyMap<string, unknown>;
  responseCapturedAt?: ReadonlyMap<string, number>;
  requiredVariables?: readonly string[];
  cache?: Map<string, ReplayVariableCacheEntry>;
}): ReplayVariableResolution {
  const now = args.now ?? Date.now();
  const values: Record<string, string> = { BASE_URL: new URL(args.baseUrl).origin };
  const diagnostics: ReplayVariableDiagnostic[] = [];
  const required = args.requiredVariables ? new Set(args.requiredVariables) : undefined;
  for (const [name, rawDefinition] of Object.entries(args.definitions)) {
    if (required && !required.has(name)) continue;
    const definition =
      typeof rawDefinition === 'string' ? { kind: 'static' as const, value: rawDefinition } : rawDefinition;
    const kind = definition.kind ?? 'static';
    // Dynamic definitions describe how to obtain a value, not the age of that value.
    // TOTP is generated now; response extraction uses the source capture's timestamp.
    if (
      kind === 'static' &&
      definition.ttl_seconds !== undefined &&
      definition.updated_at !== undefined &&
      now - Date.parse(definition.updated_at) >= definition.ttl_seconds * 1000
    ) {
      diagnostics.push({ name, kind, status: 'expired', message: 'The saved value exceeded its TTL.' });
      continue;
    }
    try {
      let value: unknown;
      if (kind === 'totp' && 'value' in definition) value = generateTotp(definition.value, now);
      else if (kind === 'response_extract' && 'source_finding' in definition) {
        const cached = args.cache?.get(name);
        const signature = JSON.stringify(definition);
        const ttl = definition.ttl_seconds;
        if (
          definition.refresh === 'on_ttl_expiry' &&
          ttl !== undefined &&
          cached?.definition === signature &&
          now - cached.capturedAt < ttl * 1000
        ) {
          values[name] = cached.value;
          diagnostics.push({ name, kind, status: 'resolved' });
          continue;
        }
        args.cache?.delete(name);
        const response = args.responseBodies?.get(definition.source_finding);
        value = extractPointer(response, definition.pointer);
        if (value === undefined) {
          diagnostics.push({
            name,
            kind,
            status: 'extract_failed',
            message: 'The configured response pointer did not resolve.',
          });
          continue;
        }
        const sourceTime = args.responseCapturedAt?.get(definition.source_finding);
        if (ttl !== undefined && (sourceTime === undefined || now - sourceTime >= ttl * 1000)) {
          diagnostics.push({
            name,
            kind,
            status: 'expired',
            message: 'The source response is stale or has no capture timestamp; refresh the source flow.',
          });
          continue;
        }
        if (['string', 'number'].includes(typeof value) && value !== '' && sourceTime !== undefined)
          args.cache?.set(name, { definition: signature, value: String(value), capturedAt: sourceTime });
      } else value = 'value' in definition ? definition.value : undefined;
      if (!['string', 'number'].includes(typeof value) || value === '') {
        diagnostics.push({
          name,
          kind,
          status: 'missing',
          message: 'The variable resolved to an empty or unsupported value.',
        });
        continue;
      }
      values[name] = String(value);
      diagnostics.push({ name, kind, status: 'resolved' });
    } catch (error) {
      diagnostics.push({
        name,
        kind,
        status: 'invalid',
        message: error instanceof Error ? error.message : 'Invalid variable.',
      });
    }
  }
  for (const name of required ?? []) {
    if (!['BASE_URL', 'XSS_MARKER'].includes(name) && !Object.hasOwn(args.definitions, name))
      diagnostics.push({ name, kind: 'static', status: 'missing', message: 'No saved input definition exists.' });
  }
  return { values, diagnostics };
}

/** Scope and refresh each finding independently; caches contain secrets only in memory. */
export function createReplayVariableResolver(deliverablesDir: string, baseUrl: string) {
  const caches = new Map<string, Map<string, ReplayVariableCacheEntry>>();
  return async (
    findingId: string,
    definitions: Record<string, ReplayVariableDefinition>,
    plans: { httpPlan?: HttpReplayPlan; browserPlan?: BrowserReplayPlan },
  ): Promise<ReplayVariableResolution> => {
    let cache = caches.get(findingId);
    if (!cache) {
      cache = new Map();
      caches.set(findingId, cache);
    }
    const requiredVariables = [
      ...(plans.httpPlan ? missingReplayVariables(plans.httpPlan, {}) : []),
      ...(plans.browserPlan ? browserReplayVariableNames(plans.browserPlan) : []),
    ];
    return resolveReplayVariables({
      definitions,
      baseUrl,
      requiredVariables,
      cache,
      ...(await loadReplayResponses(deliverablesDir)),
    });
  };
}

/** Compatibility loader: structured variables are resolved for the current attempt. */
export async function loadReplayVariables(directory: string, findingId: string): Promise<Record<string, string>> {
  const definitions = await loadReplayVariableDefinitions(directory, findingId);
  const resolution = resolveReplayVariables({ definitions, baseUrl: 'http://replay.invalid' });
  const { BASE_URL: _baseUrl, ...values } = resolution.values;
  return values;
}

/** Require custom inputs before accepting a plan, respecting extraction order. */
export function missingReplayVariables(
  plan: HttpReplayPlan,
  values: Record<string, string> | Record<string, ReplayVariableDefinition>,
  configured: readonly string[] = [],
  browserPlan?: BrowserReplayPlan,
): string[] {
  const available = new Set(['BASE_URL', ...configured, ...Object.keys(values).filter((key) => values[key])]);
  const missing = new Set<string>();
  for (const step of [...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])]) {
    const input = JSON.stringify({
      url: step.url,
      headers: step.headers,
      body: step.body,
      body_json: step.body_json,
      multipart: step.multipart,
      expect: step.expect,
    });
    for (const match of input.matchAll(/\$\{([A-Za-z][A-Za-z0-9_]*)\}/g)) {
      const captured = match[1];
      if (captured === undefined) continue;
      const name = captured.toUpperCase();
      if (!available.has(name)) missing.add(name);
    }
    for (const name of [...Object.keys(step.save_json ?? {}), ...Object.keys(step.save_headers ?? {})])
      available.add(name.toUpperCase());
  }
  // HTTP extraction supplies only the HTTP runner. Browser replay needs its own saved
  // definition (possibly pointing at that response) or a configured input.
  const browserAvailable = new Set([
    'BASE_URL',
    'XSS_MARKER',
    ...configured,
    ...Object.keys(values).filter((key) => values[key]),
  ]);
  for (const name of browserPlan ? browserReplayVariableNames(browserPlan) : [])
    if (!browserAvailable.has(name)) missing.add(name);
  return [...missing].sort();
}

/** Update only input variables actually consumed by a plan, never response-derived values. */
export async function updateReplayVariables(
  directory: string,
  findingId: string,
  plan: HttpReplayPlan,
  updates: Record<string, string>,
  configured: readonly string[] = [],
  baseline: Readonly<Record<string, ReplayVariableDefinition>> = {},
  browserPlan?: BrowserReplayPlan,
): Promise<string[]> {
  if (!validFindingId(findingId)) throw new Error('Invalid finding ID');
  const content = JSON.stringify({
    steps: [...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])].map((step) => ({
      url: step.url,
      headers: step.headers,
      body: step.body,
      body_json: step.body_json,
      multipart: step.multipart,
      expect: step.expect,
    })),
  });
  const referenced = new Set(
    [...content.matchAll(/\$\{([A-Za-z][A-Za-z0-9_]*)\}/g)].flatMap((match) =>
      match[1] === undefined ? [] : [match[1].toUpperCase()],
    ),
  );
  for (const name of browserPlan ? browserReplayVariableNames(browserPlan) : []) referenced.add(name);
  const extracted = new Set(
    [...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])].flatMap((step) =>
      [...Object.keys(step.save_json ?? {}), ...Object.keys(step.save_headers ?? {})].map((name) => name.toUpperCase()),
    ),
  );
  const protectedNames = new Set([
    'BASE_URL',
    'XSS_MARKER',
    ...configured.map((name) => name.toUpperCase()),
    ...extracted,
  ]);
  const normalized: Record<string, string> = {};
  for (const [rawName, value] of Object.entries(updates)) {
    const name = rawName.toUpperCase();
    if (!/^[A-Z][A-Z0-9_]*$/.test(name) || typeof value !== 'string' || value.includes('\0'))
      throw new Error('Variable names and values must be valid strings.');
    if (!referenced.has(name)) throw new Error(`Variable ${name} is not referenced by this replay plan.`);
    if (protectedNames.has(name))
      throw new Error(`Variable ${name} is supplied by configuration or extracted from an earlier response.`);
    if (Object.hasOwn(normalized, name)) throw new Error(`Variable ${name} was supplied more than once.`);
    normalized[name] = value;
  }
  if (!Object.keys(normalized).length) throw new Error('Supply at least one referenced replay variable.');

  const current = await loadReplayVariableDefinitions(directory, findingId);
  const merged = { ...baseline, ...current, ...normalized };
  const missing = missingReplayVariables(plan, merged, configured, browserPlan);
  if (missing.length) throw new Error(`The replay still has missing variables: ${missing.join(', ')}.`);
  if (Buffer.byteLength(JSON.stringify(merged), 'utf8') > 65536) throw new Error('Replay variable file is too large.');

  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.chmod(directory, 0o700);
  const file = path.join(directory, `${findingId}.json`);
  try {
    const existing = await fs.lstat(file);
    if (!existing.isFile() || existing.isSymbolicLink()) throw new Error('Invalid variable file');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const temporary = path.join(directory, `.${findingId}.${randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, `${JSON.stringify(merged, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    await fs.chmod(temporary, 0o600);
    await fs.rename(temporary, file);
  } finally {
    await fs.rm(temporary, { force: true });
  }
  return Object.keys(normalized).sort();
}
