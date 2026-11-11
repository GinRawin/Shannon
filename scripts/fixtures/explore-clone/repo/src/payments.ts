import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export async function getPaymentById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const paymentId = req.params.id;
  const payment = await pool.query(`SELECT id, amount FROM payments WHERE id = '${paymentId}'`);
  if (!payment) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ payment });
}
