import { pool } from './pool.js';

export async function fetchNote(id: string): Promise<unknown> {
  const note = await pool.query(`SELECT id, body FROM notes WHERE id = '${id}'`);
  return note;
}
