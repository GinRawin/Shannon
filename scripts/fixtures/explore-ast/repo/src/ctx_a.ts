import { pool } from './pool.js';

export async function guarded(authorized: boolean, id: string): Promise<unknown> {
  const marker = `m:${id}`;
  const started = 1;
  if (authorized) {
    const tagged = marker;
    const ready = started === 1;
    return pool.query(`SELECT id FROM guarded WHERE id = '${id}'`);
  }
  return marker;
}
