import type { OrderRequest, OrderResponse } from './orders.js';
import { audit, pool } from './pool.js';

export async function logAndLoad(req: OrderRequest, res: OrderResponse): Promise<void> {
  const id = req.params.id;
  audit('multi.read'); const order = await pool.query(`SELECT id, total FROM orders WHERE id = '${id}'`);
  res.json({ order });
}
