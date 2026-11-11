import type { OrderRequest, OrderResponse } from './orders.js';
import { pool } from './pool.js';

export interface DocumentRow {
  id: string;
  title: string;
}

export async function getDocumentById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const docId = req.params.id;
  const document = await pool.query(`SELECT id, title FROM documents WHERE id = '${docId}'`);
  const recorded = { action: 'read', entity: 'document', at: Date.now() };
  if (!document) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ document, recorded });
}
