import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export interface AdminRequest extends OrderRequest {
  user: { isAdmin: boolean };
}

export async function getAdminOrder(req: AdminRequest, res: OrderResponse): Promise<void> {
  if (!req.user.isAdmin) {
    res.json({ error: 'forbidden' });
    return;
  }
  const orderId = req.params.id;
  const order = await pool.query(`SELECT id, total FROM orders WHERE id = '${orderId}'`);
  const audited = { action: 'read', entity: 'order', at: Date.now() };
  if (!order) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ order, audited });
}
