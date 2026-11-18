import { pool } from './pool.js';

export async function loadThing(id: string): Promise<unknown> {
  const thing = await pool.query(`SELECT id FROM things WHERE id = '${id}'`);
  return thing;
}
