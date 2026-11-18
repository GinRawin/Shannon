import { pool } from './pool.js';

export interface 请求 {
  params: { id: string };
}

export interface 响应 {
  json: (value: unknown) => void;
}

export async function 查询订单(req: 请求, res: 响应): Promise<void> {
  const 订单号 = req.params.id;
  const 说明 = '查询订单';
  const 订单 = await pool.query(
    `SELECT id, total FROM orders WHERE id = '${订单号}'`,
    [说明],
  );
  res.json({ 说明, 订单 });
}
