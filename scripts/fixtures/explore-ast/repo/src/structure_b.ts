import { audit, pool } from './pool.js';

export async function loadThing(id: string): Promise<unknown> {
  const thing = await pool.query(`SELECT id FROM things WHERE id = '${id}'`);
  if (!thing) {
    audit('missing');
    return undefined;
  }
  return thing;
}
