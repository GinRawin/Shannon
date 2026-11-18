import { pool } from './pool.js';

export async function loadShape(id: string, flag: boolean): Promise<unknown> {
  const label = `shape:${id}`;
  const ready = flag === true;
  const first = await pool.query(`SELECT id FROM shapes WHERE id = '${id}'`);
  const second = await pool.query(`SELECT id FROM shapes WHERE id = '${id}'`);
  return { first, second, label, ready };
}
