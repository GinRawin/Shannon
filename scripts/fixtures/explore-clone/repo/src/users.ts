import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export async function getUserById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const userId = req.params.id;
  const user = await pool.query(`SELECT id, email FROM users WHERE id = '${userId}'`);
  const audited = { action: 'read', entity: 'user', at: Date.now() };
  if (!user) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ user, audited });
}
