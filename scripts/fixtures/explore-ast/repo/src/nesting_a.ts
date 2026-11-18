export function guardPair(enabled: boolean, allowed: boolean, execute: () => void): void {
  if (enabled) {
    if (allowed) execute();
  }
}
