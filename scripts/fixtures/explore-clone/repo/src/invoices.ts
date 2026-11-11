import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export async function getInvoiceById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const invoiceId = req.params.id;
  const invoice = await pool.query(`SELECT id, amount FROM invoices WHERE id = '${invoiceId}'`);
  const audited = { action: 'read', entity: 'invoice', at: Date.now() };
  if (!invoice) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ invoice, audited });
}
