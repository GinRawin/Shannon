// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Process-wide pacing for billable model requests.
 *
 * A scan can run many Temporal activities and pi sub-agents concurrently, but they
 * all live in one worker process. Every ModelRuntime created by that process is
 * therefore wrapped with the same limiter. Requests are evenly spaced instead of
 * released in a burst: at 10 RPM, starts are at least six seconds apart.
 */

import { lazyStream } from '@earendil-works/pi-ai';
import type { ModelRuntime } from '@earendil-works/pi-coding-agent';

const MINUTE_MS = 60_000;

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

/** Configure the one limiter shared by every model runtime in this worker. */
export function configureLlmRequestRateLimit(requestsPerMinute: number | undefined): void {
  processLimiter = requestsPerMinute === undefined ? undefined : new LlmRequestRateLimiter(requestsPerMinute);
}

/**
 * Intercept ModelRuntime's two streaming entry points. Its complete/completeSimple
 * methods delegate to these methods, so all normal pi agent turns and Shannon's
 * one-shot structured generations pass through this boundary.
 */
export function applyLlmRequestRateLimit(runtime: ModelRuntime): ModelRuntime {
  const limiter = processLimiter;
  if (limiter === undefined) return runtime;

  const originalStream = runtime.stream.bind(runtime);
  const originalStreamSimple = runtime.streamSimple.bind(runtime);

  runtime.stream = ((model, context, options) =>
    lazyStream(model, async () => {
      await limiter.acquire(options?.signal);
      // Hidden SDK retries would be extra HTTP requests that bypass this queue.
      // Let Shannon's Temporal retry boundary re-enter through the limiter instead.
      const limitedOptions = { ...options, maxRetries: 0 } as NonNullable<typeof options>;
      return originalStream(model, context, limitedOptions);
    })) as ModelRuntime['stream'];

  runtime.streamSimple = ((model, context, options) =>
    lazyStream(model, async () => {
      await limiter.acquire(options?.signal);
      const limitedOptions = { ...options, maxRetries: 0 } as NonNullable<typeof options>;
      return originalStreamSimple(model, context, limitedOptions);
    })) as ModelRuntime['streamSimple'];

  return runtime;
}
