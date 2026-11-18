// Type-1 clone of orders.ts: same statements, only formatting and comments differ.
import type { QueryResult } from './pool.js';
import { pool } from './pool.js';

export interface OrderRequest {
  params: { id: string };
}

export interface OrderResponse {
  json: (value: unknown) => void;
}

export async function getOrderById(req: OrderRequest, res: OrderResponse): Promise<void> {
    const orderId = req.params.id;

    /* load the requested row */
    const order = await pool.query(
      `SELECT id, total FROM orders WHERE id = '${orderId}'`,
    );
    const audited = { action: 'read', entity: 'order', at: Date.now() };
    if (!order) {
      res.json({ error: 'not found' });
      return;
    }
    res.json({ order, audited });
}
