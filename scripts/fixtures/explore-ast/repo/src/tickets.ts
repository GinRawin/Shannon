import type { OrderRequest, OrderResponse } from './orders.js';
import { logger, pool } from './pool.js';

export async function getTicketById(req: OrderRequest, res: OrderResponse): Promise<void> {
  const ticketId = req.params.id;
  logger.debug('ticket lookup');
  const ticket = await pool.query(`SELECT id, subject FROM tickets WHERE id = '${ticketId}'`);
  const tracked = { action: 'read', entity: 'ticket', at: Date.now() };
  if (!ticket) {
    res.json({ error: 'not found' });
    return;
  }
  res.json({ ticket, tracked });
}
