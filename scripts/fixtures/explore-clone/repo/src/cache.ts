export interface CacheEntry {
  key: string;
  expiresAt: number;
}

const entries = new Map<string, CacheEntry>();

export function getOrderById(key: string): CacheEntry | undefined {
  const entry = entries.get(key);
  if (entry === undefined) return undefined;
  if (entry.expiresAt < Date.now()) {
    entries.delete(key);
    return undefined;
  }
  return entry;
}

export function remember(key: string, entry: CacheEntry): CacheEntry {
  entries.set(key, entry);
  return entry;
}
