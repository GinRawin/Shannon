export interface MetricPoint {
  name: string;
  value: number;
}

export const registry = new Map<string, number>();

export function audit(name: string, value = 1): void {
  registry.set(name, (registry.get(name) ?? 0) + value);
}

export function snapshot(): MetricPoint[] {
  return [...registry.entries()].map(([name, value]) => ({ name, value }));
}
