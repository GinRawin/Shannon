/** Structured provider error envelopes, including the pinned Pi SDK's serialized form. */

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** Ark's per-minute token limit is temporary; it is not an exhausted account balance. */
export function isTpmRateLimitBody(value: unknown): boolean {
  const body = record(value);
  const code = record(body?.error)?.code ?? body?.code;
  return code === 'ModelAccountTpmRateLimitExceeded';
}

/**
 * Pi formats SDK HTTP errors as `429: {"code":...}`. Recover only this exact JSON
 * envelope, not status-like digits or rate-limit keywords embedded in free text.
 */
export function serializedProviderError(error: unknown): { status: number; body: unknown } | undefined {
  const value = record(error);
  const text = value?.errorMessage ?? (error instanceof Error ? error.message : undefined);
  if (typeof text !== 'string' || text.length > 65_536) return undefined;
  const match = /^([1-5]\d{2}):\s*(\{[\s\S]*\})$/u.exec(text);
  if (!match?.[1] || !match[2]) return undefined;
  try {
    const body: unknown = JSON.parse(match[2]);
    return record(body) ? { status: Number(match[1]), body } : undefined;
  } catch {
    return undefined;
  }
}
