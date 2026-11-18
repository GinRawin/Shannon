import type { OrderRequest, OrderResponse } from './orders.js';
import type { QueryResult } from './pool.js';
import { pool } from './pool.js';

export interface DocumentRow {
  id: string;
  title: string;
}

export async function getDocumentById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const documentId = req.params.id;
  const document = await pool.query(`SELECT id, title FROM documents WHERE id = '${documentId}'`);
  const recorded = { action: 'read', entity: 'document', at: Date.now() };
  if (!document) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ document, recorded });
}
