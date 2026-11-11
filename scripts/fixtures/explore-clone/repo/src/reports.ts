import type { OrderRequest, OrderResponse } from './orders.js';
import { audit } from './metrics.js';
import { pool } from './pool.js';

export async function getReportById(req: OrderRequest, res: OrderResponse): Promise<void> {
  audit('reports.read');
  const reportId = req.params.id;
  const found = await pool.query(`SELECT id, body FROM reports WHERE id = '${reportId}'`);
  const tracked = { action: 'read', entity: 'report', at: Date.now() };
  if (!found) return res.json({ error: 'not found' });
  res.json({ report: found, tracked });
}
