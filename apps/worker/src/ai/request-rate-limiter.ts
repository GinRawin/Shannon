// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Process-wide pacing and 429 recovery for billable model requests.
 *
 * A scan can run many Temporal activities and pi sub-agents concurrently, but they
 * all live in one worker process. Every ModelRuntime created by that process is
 * therefore wrapped with the same limiter. Requests are evenly spaced instead of
 * released in a burst: at 10 RPM, starts are at least six seconds apart.
 *
 * A provider 429 also opens one process-wide exponential backoff window. That is
 * important when several agents share a low RPM allowance: without a shared window,
 * every in-flight session independently retries and creates another burst as soon as
 * its short SDK delay expires. Provider retries still happen in-session, but every
 * retry passes through this boundary before another HTTP request starts.
 */

import { lazyStream } from '@earendil-works/pi-ai';
import type { ModelRuntime } from '@earendil-works/pi-coding-agent';
import { isTpmRateLimitBody } from './provider-rate-limit.js';

const MINUTE_MS = 60_000;
const DEFAULT_429_BACKOFF_BASE_MS = 15_000;
const MAX_429_BACKOFF_MS = 5 * MINUTE_MS;

interface QueuedRequest {
  readonly resolve: () => void;
  readonly reject: (reason: unknown) => void;
  readonly signal?: AbortSignal;
  onAbort?: () => void;
}

export class LlmRequestRateLimiter {
  private readonly queue: QueuedRequest[] = [];
  private lastStartAt = Number.NEGATIVE_INFINITY;
  private timer: NodeJS.Timeout | undefined;
  readonly intervalMs: number;

  constructor(readonly requestsPerMinute: number) {
    if (!Number.isSafeInteger(requestsPerMinute) || requestsPerMinute <= 0) {
      throw new Error('LLM requests per minute must be a positive integer');
    }
    this.intervalMs = Math.ceil(MINUTE_MS / requestsPerMinute);
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    await new Promise<void>((resolve, reject) => {
      const entry: QueuedRequest = { resolve, reject, ...(signal !== undefined && { signal }) };
      if (signal !== undefined) {
        entry.onAbort = () => {
          const index = this.queue.indexOf(entry);
          if (index === -1) return;
          this.queue.splice(index, 1);
          try {
            signal.throwIfAborted();
          } catch (reason) {
            reject(reason);
          }
          // If the head disappeared, its timer may no longer represent useful work.
          if (index === 0) {
            this.clearTimer();
            this.scheduleNext();
          }
        };
        signal.addEventListener('abort', entry.onAbort, { once: true });
      }
      this.queue.push(entry);
      this.scheduleNext();
    });
  }

  private clearTimer(): void {
    if (this.timer === undefined) return;
    clearTimeout(this.timer);
    this.timer = undefined;
  }

  private scheduleNext(): void {
    if (this.timer !== undefined || this.queue.length === 0) return;
    const delayMs = Math.max(0, this.lastStartAt + this.intervalMs - Date.now());
    if (delayMs > 0) {
      this.timer = setTimeout(() => {
        this.timer = undefined;
        this.releaseNext();
      }, delayMs);
      return;
    }
    this.releaseNext();
  }

  private releaseNext(): void {
    const entry = this.queue.shift();
    if (entry === undefined) return;
    if (entry.signal !== undefined && entry.onAbort !== undefined) {
      entry.signal.removeEventListener('abort', entry.onAbort);
    }
    this.lastStartAt = Date.now();
    entry.resolve();
    this.scheduleNext();
  }
}

let processLimiter: LlmRequestRateLimiter | undefined;

function abortableDelay(delayMs: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, delayMs);
    const onAbort = (): void => {
      clearTimeout(timer);
      try {
        signal?.throwIfAborted();
      } catch (reason) {
        reject(reason);
      }
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function retryAfterMs(headers: Headers, now: number): number | undefined {
  const milliseconds = headers.get('retry-after-ms');
  if (milliseconds !== null) {
    const parsed = Number.parseFloat(milliseconds);
    if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  }

  const retryAfter = headers.get('retry-after');
  if (retryAfter === null) return undefined;
  const seconds = Number.parseFloat(retryAfter);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(retryAfter);
  return Number.isFinite(date) && date > now ? date - now : undefined;
}

/**
 * One recovery gate shared by all model runtimes in the worker.
 *
 * The generation token prevents an older concurrent success from clearing a newer
 * 429. A request that starts after the current cooldown and succeeds resets the
 * exponent; requests already in flight when the 429 arrived cannot do so.
 */
export class Llm429Backoff {
  private consecutive429s = 0;
  private blockedUntil = 0;
  private generation = 0;

  constructor(
    readonly baseDelayMs: number = DEFAULT_429_BACKOFF_BASE_MS,
    readonly maxDelayMs: number = MAX_429_BACKOFF_MS,
  ) {
    if (!Number.isFinite(baseDelayMs) || baseDelayMs <= 0) {
      throw new Error('429 backoff base delay must be positive');
    }
    if (!Number.isFinite(maxDelayMs) || maxDelayMs < baseDelayMs) {
      throw new Error('429 backoff maximum delay must be at least the base delay');
    }
  }

  async wait(signal?: AbortSignal): Promise<number> {
    for (;;) {
      signal?.throwIfAborted();
      const delayMs = this.blockedUntil - Date.now();
      if (delayMs <= 0) return this.generation;
      await abortableDelay(delayMs, signal);
      // Another concurrent 429 may have extended the window while this request slept.
    }
  }

  observe(response: Response, requestGeneration: number, tpmLimited = false): void {
    if (response.status === 429) {
      const now = Date.now();
      const exponent = Math.min(this.consecutive429s, 30);
      // A token-per-minute bucket needs a full minute to replenish, rather than
      // the shorter initial recovery window used for ordinary request limits.
      const baseDelayMs = tpmLimited ? Math.max(this.baseDelayMs, MINUTE_MS) : this.baseDelayMs;
      const exponentialDelay = Math.min(this.maxDelayMs, baseDelayMs * 2 ** exponent);
      const providerDelay = retryAfterMs(response.headers, now) ?? 0;
      const delayMs = Math.min(this.maxDelayMs, Math.max(exponentialDelay, providerDelay));

      this.consecutive429s += 1;
      this.generation += 1;
      this.blockedUntil = Math.max(this.blockedUntil, now + delayMs);
      console.warn(`LLM ${tpmLimited ? 'TPM' : '429'} limit: shared cooldown ${Math.ceil(delayMs / 1000)}s`);
      return;
    }

    if (response.ok && requestGeneration === this.generation) {
      this.consecutive429s = 0;
      this.blockedUntil = 0;
    }
  }
}

let process429Backoff = new Llm429Backoff();

/** Configure the one limiter shared by every model runtime in this worker. */
export function configureLlmRequestRateLimit(requestsPerMinute: number | undefined): void {
  processLimiter = requestsPerMinute === undefined ? undefined : new LlmRequestRateLimiter(requestsPerMinute);
  // A configured low RPM is also the safest first recovery window. With no explicit
  // limit, use a conservative 15 seconds and grow from there.
  const baseDelayMs = Math.max(DEFAULT_429_BACKOFF_BASE_MS, processLimiter?.intervalMs ?? 0);
  process429Backoff = new Llm429Backoff(baseDelayMs);
}

function requestSignal(
  input: Parameters<typeof globalThis.fetch>[0],
  init: RequestInit | undefined,
  fallback?: AbortSignal,
): AbortSignal {
  if (init?.signal) return init.signal;
  if (input instanceof Request) return input.signal;
  return fallback ?? new AbortController().signal;
}

function backoffFetch(
  fetchImplementation: typeof globalThis.fetch,
  limiter: LlmRequestRateLimiter | undefined,
  backoff: Llm429Backoff,
  fallbackSignal?: AbortSignal,
  firstReservationGeneration?: number,
): typeof globalThis.fetch {
  // The outer runtime wrapper already reserves the first HTTP request. Provider SDK
  // retries reuse this fetch function, so every later attempt re-enters the RPM queue.
  // If a concurrent 429 invalidated that first reservation, reserve it again after
  // the new cooldown rather than releasing a burst of stale reservations together.
  let firstRequest = true;
  return async (input, init) => {
    const signal = requestSignal(input, init, fallbackSignal);
    let generation = await backoff.wait(signal);
    const hasValidFirstReservation = firstRequest && generation === firstReservationGeneration;
    firstRequest = false;
    if (!hasValidFirstReservation) {
      generation = await reserveRequestStart(limiter, backoff, signal);
    }
    const response = await fetchImplementation(input, init);
    let tpmLimited = false;
    if (response.headers.get('content-type')?.includes('application/json')) {
      // Inspect a clone so the SDK can still read the original error body.
      try {
        tpmLimited = isTpmRateLimitBody(await response.clone().json());
      } catch {
        // Malformed/non-JSON errors still use their HTTP status for recovery.
      }
    }
    // Some compatible gateways keep a provider's TPM code but replace its HTTP
    // status. Present that explicit transient error as 429 so SDK retries apply.
    const retryResponse =
      tpmLimited && response.status !== 429
        ? new Response(response.body, { status: 429, statusText: 'Too Many Requests', headers: response.headers })
        : response;
    backoff.observe(retryResponse, generation, tpmLimited);
    return retryResponse;
  };
}

async function reserveRequestStart(
  limiter: LlmRequestRateLimiter | undefined,
  backoff: Llm429Backoff,
  signal?: AbortSignal,
): Promise<number> {
  for (;;) {
    const generation = await backoff.wait(signal);
    await limiter?.acquire(signal);
    const currentGeneration = await backoff.wait(signal);
    if (limiter === undefined || currentGeneration === generation) return currentGeneration;
    // The reservation was made before a concurrent 429 extended the cooldown.
    // Discard it and enter the pacing queue again after the new window expires.
  }
}

/**
 * Intercept ModelRuntime's two streaming entry points. Its complete/completeSimple
 * methods delegate to these methods, so all normal pi agent turns and Shannon's
 * one-shot structured generations pass through this boundary.
 */
export function applyLlmRequestRateLimit(runtime: ModelRuntime): ModelRuntime {
  const limiter = processLimiter;
  const backoff = process429Backoff;

  const originalStream = runtime.stream.bind(runtime);
  const originalStreamSimple = runtime.streamSimple.bind(runtime);

  runtime.stream = ((model, context, options) =>
    lazyStream(model, async () => {
      const generation = await reserveRequestStart(limiter, backoff, options?.signal);
      const limitedOptions = {
        ...options,
        fetch: backoffFetch(options?.fetch ?? globalThis.fetch, limiter, backoff, options?.signal, generation),
      } as NonNullable<typeof options>;
      return originalStream(model, context, limitedOptions);
    })) as ModelRuntime['stream'];

  runtime.streamSimple = ((model, context, options) =>
    lazyStream(model, async () => {
      const generation = await reserveRequestStart(limiter, backoff, options?.signal);
      const limitedOptions = {
        ...options,
        fetch: backoffFetch(options?.fetch ?? globalThis.fetch, limiter, backoff, options?.signal, generation),
      } as NonNullable<typeof options>;
      return originalStreamSimple(model, context, limitedOptions);
    })) as ModelRuntime['streamSimple'];

  return runtime;
}
