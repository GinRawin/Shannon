import { audit } from './pool.js';

export function guardPair(enabled: boolean, allowed: boolean, execute: () => void): void {
  if (allowed) execute();
  if (enabled) audit('skipped');
}
