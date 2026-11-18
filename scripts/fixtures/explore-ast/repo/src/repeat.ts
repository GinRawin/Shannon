import { pool } from './pool.js';

export interface LookupRequest {
  params: { id: string };
}

export interface LookupResponse {
  json: (value: unknown) => void;
}

export async function loadLeft(req: LookupRequest, res: LookupResponse): Promise<void> {
  const key = req.params.id;
  const row = await pool.query(`SELECT id, label FROM left_table WHERE id = '${key}'`);
  res.json({ row });
}

export async function loadRight(req: LookupRequest, res: LookupResponse): Promise<void> {
  const key = req.params.id;
  const row = await pool.query(`SELECT id, label FROM right_table WHERE id = '${key}'`);
  res.json({ row });
}
