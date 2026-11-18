import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export async function loadWidget(req: OrderRequest, res: OrderResponse): Promise<void> {
  const widgetId = req.params.id;
  const widget = await pool.query(`SELECT id, label FROM widgets WHERE id = '${widgetId}'`);
  const tracked = { action: 'read', entity: 'widget', at: Date.now() };
  if (!widget) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ widget, tracked });
}
