import type { OrderRequest, OrderResponse } from './orders.js';
import { logger, pool } from './pool.js';

export async function getReportById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const reportId = req.params.id;
  logger.debug('report lookup');
  const report = await pool.query(`SELECT id, body FROM reports WHERE id = '${reportId}'`);
  if (!report) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ report });
}
