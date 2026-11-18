import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export function makeLoader(req: OrderRequest): () => Promise<unknown> {
  return async () => {
    const orderId = req.params.id;
    const order = await pool.query(`SELECT id, total FROM orders WHERE id = '${orderId}'`);
    const audited = { action: 'read', entity: 'order', at: Date.now() };
    return { order, audited };
  };
}
