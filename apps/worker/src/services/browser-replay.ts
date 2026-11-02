import { createHash, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { type BrowserContext, chromium, type Page } from 'playwright-core';
import { type Static, Type } from 'typebox';
import { Value } from 'typebox/value';
import type { HttpEvidenceReceipt } from './capture-http-request.js';
import { containsReplaySecret } from './http-replay.js';

const text = () => Type.String({ minLength: 1, maxLength: 16000 });
const action = <T extends Record<string, import('typebox').TSchema>>(properties: T) =>
  Type.Object(properties, { additionalProperties: false });
const BrowserActionSchema = Type.Union([
  action({ action: Type.Literal('goto'), url: text() }),
  action({ action: Type.Literal('fill'), selector: text(), value: text() }),
  action({ action: Type.Literal('click'), selector: text() }),
  action({ action: Type.Literal('hover'), selector: text() }),
  action({
    action: Type.Literal('press'),
    selector: text(),
    key: Type.Union([
      Type.Literal('Enter'),
      Type.Literal('Tab'),
      Type.Literal('Escape'),
      Type.Literal('Space'),
      Type.Literal('ArrowDown'),
      Type.Literal('ArrowUp'),
    ]),
  }),
  action({ action: Type.Literal('wait_for'), selector: text() }),
]);

export const BrowserReplaySchema = Type.Object(
  {
    steps: Type.Array(BrowserActionSchema, { minItems: 1, maxItems: 30 }),
    cleanup: Type.Optional(Type.Array(BrowserActionSchema, { maxItems: 10 })),
    use_auth_state: Type.Optional(Type.Boolean()),
    insecure: Type.Optional(Type.Boolean()),
    timeout_ms: Type.Optional(Type.Integer({ minimum: 1000, maximum: 60000 })),
  },
  {
    additionalProperties: false,
    description:
      'Host-executed XSS reproduction. Only navigation and UI actions; no JavaScript evaluation. Inject alert("${XSS_MARKER}") through the proven vulnerable input. The host replaces XSS_MARKER with an unpredictable per-attempt challenge and observes the exact dialog itself.',
  },
);

export type BrowserReplayPlan = Static<typeof BrowserReplaySchema>;
export type BrowserReplayStage = 'record' | 'record-expansion' | 'record-retry';
export interface BrowserReplayVerification {
  verifier: 'playwright-host-v1';
  finding_id: string;
  stage: BrowserReplayStage;
  attempt_id: string;
  attempt: number;
  plan_sha256: string;
  http_capture_ids: string[];
  verified_at: string;
  observed_at: string;
  target_origin: string;
  page_url: string;
  assertion_type: 'dialog_exact';
  expected: string;
  observed: string;
  evidence_files: string[];
  evidence_sha256: string[];
  receipt_file: string;
  receipt_sha256: string;
}

const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
export const browserReplayPlanDigest = (plan: BrowserReplayPlan): string => digest(JSON.stringify(plan));

export function browserReplayPlanError(plan: BrowserReplayPlan): string | undefined {
  if (!Value.Check(BrowserReplaySchema, plan))
    return 'Invalid browser replay plan; only the documented navigation and UI actions are accepted.';
  if (plan.steps[0]?.action !== 'goto') return 'Browser replay must begin with a target navigation.';
  // Selectors and keyboard commands must never be programmable or variable controlled.
  for (const step of [...plan.steps, ...(plan.cleanup ?? [])]) {
    if ('selector' in step && /\$\{|\{\{/.test(step.selector)) return 'Browser selectors cannot contain variables.';
    if (step.action === 'goto' && !step.url.startsWith('${BASE_URL}'))
      return 'Browser navigation must begin with ${BASE_URL}.';
  }
  if (
    !plan.steps.some((step) =>
      (step.action === 'goto' ? step.url : step.action === 'fill' ? step.value : '').includes('${XSS_MARKER}'),
    )
  )
    return 'The proven browser payload must contain ${XSS_MARKER} and trigger a dialog with exactly that value.';
  return undefined;
}

export function browserReplayVariableNames(plan: BrowserReplayPlan): string[] {
  return [
    ...new Set(
      [...plan.steps, ...(plan.cleanup ?? [])].flatMap((step) =>
        [
          ...(step.action === 'goto' ? step.url : step.action === 'fill' ? step.value : '').matchAll(
            /\$\{([A-Z][A-Z0-9_]*)\}/g,
          ),
        ].flatMap((match) => (match[1] && !['BASE_URL', 'XSS_MARKER'].includes(match[1]) ? [match[1]] : [])),
      ),
    ),
  ];
}

/** Reuse HTTP literal-secret checks for browser inputs and navigation query values. */
export function browserReplayContainsSecrets(plan: BrowserReplayPlan, secrets: readonly string[]): boolean {
  return containsReplaySecret(
    {
      steps: [...plan.steps, ...(plan.cleanup ?? [])].map((step) => ({
        method: 'GET' as const,
        url: step.action === 'goto' ? step.url : '${BASE_URL}/',
        ...(step.action === 'fill' ? { body_json: { value: step.value } } : {}),
      })),
    },
    secrets,
  );
}

/** No workspace scripts, browser daemon, evaluate action, or caller-provided observation enters this runner. */
export async function verifyBrowserReplay(args: {
  findingId: string;
  stage: BrowserReplayStage;
  attempt: number;
  plan: BrowserReplayPlan;
  variables: Record<string, string>;
  httpEvidence: readonly HttpEvidenceReceipt[];
  targetUrl: string;
  deliverablesDir: string;
  authStatePath?: string;
  signal?: AbortSignal | undefined;
}): Promise<{ verification?: BrowserReplayVerification; error?: string }> {
  const invalid = browserReplayPlanError(args.plan);
  if (invalid) return { error: invalid };
  if (
    !/^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(args.findingId) ||
    !Number.isInteger(args.attempt) ||
    args.attempt < 1
  )
    return { error: 'Invalid browser replay identity.' };
  if (
    !args.httpEvidence.length ||
    args.httpEvidence.some((receipt) => !receipt.complete || receipt.finding_id !== args.findingId)
  )
    return { error: "Browser replay requires this finding's complete HTTP replay receipts." };
  let origin: string;
  try {
    const target = new URL(args.targetUrl);
    if (!['http:', 'https:'].includes(target.protocol)) return { error: 'Invalid browser replay target.' };
    origin = target.origin;
  } catch {
    return { error: 'Invalid browser replay target.' };
  }
  const attemptId = randomUUID();
  const marker = `shannon_xss_${randomBytes(24).toString('hex')}`;
  const variables = { ...args.variables, BASE_URL: origin, XSS_MARKER: marker };
  const interpolate = (value: string): string =>
    value.replace(/\$\{([A-Z][A-Z0-9_]*)\}/g, (_match, name: string) => {
      const resolved = variables[name as keyof typeof variables];
      if (resolved === undefined || resolved === '') throw new Error(`Missing browser replay variable: ${name}`);
      return resolved;
    });
  const relative = `browser-replay-verifications/${args.findingId}/${attemptId}`;
  const directory = path.join(args.deliverablesDir, relative);
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const abort = () => {
    void browser?.close().catch(() => {});
  };
  let phase = 'plan_variables';
  try {
    for (const step of [...args.plan.steps, ...(args.plan.cleanup ?? [])]) {
      if (step.action === 'fill') interpolate(step.value);
      if (step.action === 'goto') {
        const url = new URL(interpolate(step.url));
        if (url.origin !== origin || url.username || url.password)
          throw new Error('Browser replay navigation is outside the assessment origin.');
      }
    }
    if (args.signal?.aborted) throw new Error('Browser replay was cancelled.');
    const executablePath = process.env.PLAYWRIGHT_MCP_EXECUTABLE_PATH;
    phase = 'browser_launch';
    browser = await chromium.launch({ headless: true, timeout: 15000, ...(executablePath ? { executablePath } : {}) });
    args.signal?.addEventListener('abort', abort, { once: true });
    if (args.signal?.aborted) throw new Error('Browser replay was cancelled.');
    const deadline = args.plan.timeout_ms ?? 15000;
    timeout = setTimeout(abort, deadline);
    phase = 'authentication';
    let storageState: Awaited<ReturnType<BrowserContext['storageState']>> | undefined;
    if (args.plan.use_auth_state) {
      if (!args.authStatePath) throw new Error('Authenticated browser state is unavailable.');
      const saved = JSON.parse(await fs.readFile(args.authStatePath, 'utf8')) as NonNullable<typeof storageState>;
      const hostname = new URL(origin).hostname;
      storageState = {
        cookies: saved.cookies.filter(
          (cookie) =>
            hostname === cookie.domain.replace(/^\./, '') || hostname.endsWith(`.${cookie.domain.replace(/^\./, '')}`),
        ),
        origins: saved.origins.filter((entry) => entry.origin === origin),
      };
    }
    phase = 'browser_context';
    const context = await browser.newContext({
      serviceWorkers: 'block',
      ignoreHTTPSErrors: args.plan.insecure ?? false,
      ...(storageState ? { storageState } : {}),
    });
    context.setDefaultTimeout(Math.min(deadline, 10000));
    context.setDefaultNavigationTimeout(Math.min(deadline, 10000));
    // Playwright skips route handlers for redirects. Inspect response headers through
    // a separate Chromium session before allowing the browser to follow Location.
    const redirectGuards = new WeakMap<Page, Promise<void>>();
    const guardRedirects = (page: Page): Promise<void> => {
      let ready = redirectGuards.get(page);
      if (!ready) {
        ready = (async () => {
          const session = await context.newCDPSession(page);
          session.on('Fetch.requestPaused', (event) => {
            const location = event.responseHeaders?.find((header) => header.name.toLowerCase() === 'location')?.value;
            let allowed = true;
            if (location && [301, 302, 303, 307, 308].includes(event.responseStatusCode ?? 0)) {
              try {
                const next = new URL(location, event.request.url);
                allowed = next.origin === origin && !next.username && !next.password;
              } catch {
                allowed = false;
              }
            }
            void (
              allowed
                ? session.send('Fetch.continueRequest', { requestId: event.requestId })
                : session.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' })
            ).catch(() => {});
          });
          await session.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Response' }] });
        })();
        redirectGuards.set(page, ready);
      }
      return ready;
    };
    await context.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== origin || url.username || url.password) return route.abort('blockedbyclient');
      try {
        await guardRedirects(route.request().frame().page());
        await route.continue();
      } catch {
        await route.abort('blockedbyclient').catch(() => {});
      }
    });
    await context.routeWebSocket('**/*', (socket) => {
      if (new URL(socket.url()).origin.replace(/^ws/, 'http') === origin) socket.connectToServer();
      else socket.close();
    });
    let event: { observed: string; page_url: string; observed_at: string; page: Page } | undefined;
    let acceptEvents = true;
    let signalObserved: (() => void) | undefined;
    const observed = new Promise<void>((resolve) => {
      signalObserved = resolve;
    });
    const observe = (page: Page) => {
      void guardRedirects(page).catch(() => page.close().catch(() => {}));
      page.on('dialog', async (dialog) => {
        if (acceptEvents && dialog.message() === marker && page.url().startsWith(`${origin}/`)) {
          event = { observed: dialog.message(), page_url: page.url(), observed_at: new Date().toISOString(), page };
          signalObserved?.();
        }
        await dialog.dismiss().catch(() => {});
      });
    };
    context.on('page', observe);
    const page = await context.newPage();
    await guardRedirects(page);
    const execute = async (step: BrowserReplayPlan['steps'][number]) => {
      if (args.signal?.aborted) throw new Error('Browser replay was cancelled.');
      switch (step.action) {
        case 'goto':
          await page.goto(interpolate(step.url), { waitUntil: 'domcontentloaded' });
          break;
        case 'fill':
          await page.locator(step.selector).fill(interpolate(step.value));
          break;
        case 'click':
          await page.locator(step.selector).click();
          break;
        case 'hover':
          await page.locator(step.selector).hover();
          break;
        case 'press':
          await page.locator(step.selector).press(step.key);
          break;
        case 'wait_for':
          await page.locator(step.selector).waitFor({ state: 'visible' });
          break;
      }
    };
    let failure: unknown;
    let screenshot: Buffer | undefined;
    try {
      phase = 'browser_steps';
      for (const step of args.plan.steps) await execute(step);
      phase = 'execution_signal';
      if (!event)
        await Promise.race([
          observed,
          page.waitForTimeout(deadline).then(() => {
            throw new Error('Browser execution signal timed out.');
          }),
        ]);
      if (!event) throw new Error('No JavaScript execution dialog matched the host challenge.');
      acceptEvents = false;
      phase = 'screenshot';
      screenshot = await event.page.screenshot({ type: 'png', timeout: 5000 });
    } catch (error) {
      failure = error;
    } finally {
      acceptEvents = false;
      for (const step of args.plan.cleanup ?? []) {
        try {
          await execute(step);
        } catch {
          phase = 'cleanup';
          failure = new Error('Browser replay cleanup failed.');
        }
      }
    }
    if (failure || !event || !screenshot) throw failure ?? new Error('Browser execution evidence is incomplete.');
    if (args.signal?.aborted) throw new Error('Browser replay was cancelled.');
    phase = 'evidence_persistence';
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const evidenceFile = `${relative}/screenshot.png`;
    await fs.writeFile(path.join(directory, 'screenshot.png'), screenshot, { flag: 'wx', mode: 0o600 });
    const receipt = {
      verifier: 'playwright-host-v1' as const,
      finding_id: args.findingId,
      stage: args.stage,
      attempt_id: attemptId,
      attempt: args.attempt,
      plan_sha256: browserReplayPlanDigest(args.plan),
      http_capture_ids: args.httpEvidence.map((item) => item.capture_id),
      verified_at: new Date().toISOString(),
      target_origin: origin,
      page_url: event.page_url,
      assertion_type: 'dialog_exact' as const,
      expected: marker,
      observed: event.observed,
      observed_at: event.observed_at,
      evidence_files: [evidenceFile],
      evidence_sha256: [digest(screenshot)],
    };
    const contents = `${JSON.stringify(receipt, null, 2)}\n`;
    await fs.writeFile(path.join(directory, 'receipt.json'), contents, { flag: 'wx', mode: 0o600 });
    return { verification: { ...receipt, receipt_file: `${relative}/receipt.json`, receipt_sha256: digest(contents) } };
  } catch {
    // Browser errors can echo payloads, URLs and private credentials. Keep the public diagnostic bounded.
    return {
      error: `Host browser replay failed during ${phase}. Check the saved plan, variables, authentication, browser installation, execution signal and cleanup. No trusted JavaScript execution receipt was produced.`,
    };
  } finally {
    if (timeout) clearTimeout(timeout);
    args.signal?.removeEventListener('abort', abort);
    await browser?.close().catch(() => {});
  }
}

/** Revalidate persisted provenance on collection and report/resume; old self-reported assertions fail closed. */
export async function hasTrustedBrowserReplay(args: {
  deliverablesDir: string;
  verification: unknown;
  findingId: string;
  stage?: BrowserReplayStage | undefined;
  plan?: BrowserReplayPlan | undefined;
  httpCaptureIds: readonly string[];
  targetUrl?: string;
}): Promise<boolean> {
  try {
    const proof = args.verification as BrowserReplayVerification | undefined;
    if (
      !proof ||
      !args.plan ||
      browserReplayPlanError(args.plan) ||
      proof.verifier !== 'playwright-host-v1' ||
      proof.finding_id !== args.findingId ||
      proof.stage !== args.stage ||
      !['record', 'record-expansion', 'record-retry'].includes(proof.stage) ||
      !/^[a-f0-9-]{36}$/.test(proof.attempt_id) ||
      !Number.isInteger(proof.attempt) ||
      proof.attempt < 1 ||
      proof.plan_sha256 !== browserReplayPlanDigest(args.plan) ||
      proof.assertion_type !== 'dialog_exact' ||
      !/^shannon_xss_[a-f0-9]{48}$/.test(proof.expected) ||
      proof.observed !== proof.expected ||
      !Number.isFinite(Date.parse(proof.verified_at)) ||
      !Number.isFinite(Date.parse(proof.observed_at)) ||
      (args.targetUrl !== undefined && proof.target_origin !== new URL(args.targetUrl).origin) ||
      !['http:', 'https:'].includes(new URL(proof.target_origin).protocol) ||
      new URL(proof.page_url).origin !== proof.target_origin ||
      !Array.isArray(proof.http_capture_ids) ||
      !args.httpCaptureIds.length ||
      JSON.stringify([...proof.http_capture_ids].sort()) !== JSON.stringify([...args.httpCaptureIds].sort())
    )
      return false;
    const relative = `browser-replay-verifications/${args.findingId}/${proof.attempt_id}`;
    if (
      !Array.isArray(proof.evidence_sha256) ||
      proof.evidence_sha256.length !== 1 ||
      proof.receipt_file !== `${relative}/receipt.json` ||
      JSON.stringify(proof.evidence_files) !== JSON.stringify([`${relative}/screenshot.png`])
    )
      return false;
    const root = await fs.realpath(args.deliverablesDir);
    const read = async (file: string) => {
      const real = await fs.realpath(path.join(root, file));
      if (!real.startsWith(`${root}${path.sep}`)) throw new Error('Evidence escaped deliverables.');
      return fs.readFile(real);
    };
    const contents = await read(proof.receipt_file);
    if (digest(contents) !== proof.receipt_sha256) return false;
    const receipt = JSON.parse(contents.toString('utf8')) as Record<string, unknown>;
    const { receipt_file: _file, receipt_sha256: _hash, ...expected } = proof;
    if (JSON.stringify(receipt) !== JSON.stringify(expected)) return false;
    const screenshot = await read(proof.evidence_files[0] as string);
    return (
      screenshot.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')) &&
      digest(screenshot) === proof.evidence_sha256[0]
    );
  } catch {
    return false;
  }
}
