import { pool } from './pool.js';

export async function loadShape(id: string, flag: boolean): Promise<unknown> {
  const name = `shape:${id}`;
  const armed = flag === false;
  const left = await pool.query(`SELECT id FROM shapes WHERE id = '${id}'`);
  const right = await pool.query(`SELECT id FROM shapes WHERE id = '${id}'`);
  return { left, right, name, armed };
}
