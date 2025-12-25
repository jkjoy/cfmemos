import { Hono } from 'hono';
import {
  requireAuth,
  jsonResponse,
  errorResponse
} from '../utils/auth.js';

const app = new Hono();

// 获取当前用户的所有 webhooks
app.get('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');

    const stmt = db.prepare(`
      SELECT id, name, url, created_ts
      FROM webhooks
      WHERE user_id = ?
      ORDER BY id DESC
    `);

    const { results: webhooks } = await stmt.bind(currentUser.id).all();

    return jsonResponse(webhooks || []);
  } catch (error) {
    console.error('Error fetching webhooks:', error);
    return errorResponse('Failed to fetch webhooks', 500);
  }
});

// 创建新的 webhook
app.post('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');
    const body = await c.req.json();

    console.log('Creating webhook with body:', body);
    console.log('Current user:', currentUser);

    // 验证必需字段
    if (!body.name || !body.url) {
      console.error('Missing required fields:', { name: body.name, url: body.url });
      return errorResponse('Name and URL are required', 400);
    }

    // 验证 URL 格式
    try {
      new URL(body.url);
    } catch (e) {
      console.error('Invalid URL format:', body.url, e);
      return errorResponse('Invalid URL format', 400);
    }

    const now = Math.floor(Date.now() / 1000);
    const insertStmt = db.prepare(`
      INSERT INTO webhooks (user_id, name, url, created_ts)
      VALUES (?, ?, ?, ?)
    `);

    const result = await insertStmt.bind(
      currentUser.id,
      body.name,
      body.url,
      now
    ).run();

    console.log('Insert result:', result);

    // 获取刚插入的记录
    const getStmt = db.prepare('SELECT id, name, url, created_ts FROM webhooks WHERE id = ?');
    const webhook = await getStmt.bind(result.meta.last_row_id).first();

    console.log('Created webhook:', webhook);

    return jsonResponse(webhook);
  } catch (error) {
    console.error('Error creating webhook:', error);
    console.error('Error stack:', error.stack);
    return errorResponse('Failed to create webhook: ' + error.message, 500);
  }
});

// 获取单个 webhook
app.get('/:id', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');
    const webhookId = c.req.param('id');

    const stmt = db.prepare(`
      SELECT id, name, url, created_ts
      FROM webhooks
      WHERE id = ? AND user_id = ?
    `);

    const webhook = await stmt.bind(webhookId, currentUser.id).first();

    if (!webhook) {
      return errorResponse('Webhook not found', 404);
    }

    return jsonResponse(webhook);
  } catch (error) {
    console.error('Error fetching webhook:', error);
    return errorResponse('Failed to fetch webhook', 500);
  }
});

// 更新 webhook
app.patch('/:id', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');
    const webhookId = c.req.param('id');
    const body = await c.req.json();

    // 验证 webhook 是否存在且属于当前用户
    const checkStmt = db.prepare('SELECT id FROM webhooks WHERE id = ? AND user_id = ?');
    const existing = await checkStmt.bind(webhookId, currentUser.id).first();

    if (!existing) {
      return errorResponse('Webhook not found', 404);
    }

    // 验证 URL 格式（如果提供）
    if (body.url) {
      try {
        new URL(body.url);
      } catch (e) {
        return errorResponse('Invalid URL format', 400);
      }
    }

    const updateStmt = db.prepare(`
      UPDATE webhooks
      SET name = COALESCE(?, name),
          url = COALESCE(?, url)
      WHERE id = ? AND user_id = ?
    `);

    await updateStmt.bind(
      body.name || null,
      body.url || null,
      webhookId,
      currentUser.id
    ).run();

    // 返回更新后的 webhook
    const getStmt = db.prepare('SELECT id, name, url, created_ts FROM webhooks WHERE id = ?');
    const webhook = await getStmt.bind(webhookId).first();

    return jsonResponse(webhook);
  } catch (error) {
    console.error('Error updating webhook:', error);
    return errorResponse('Failed to update webhook', 500);
  }
});

// 删除 webhook
app.delete('/:id', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');
    const webhookId = c.req.param('id');

    const deleteStmt = db.prepare('DELETE FROM webhooks WHERE id = ? AND user_id = ?');
    const result = await deleteStmt.bind(webhookId, currentUser.id).run();

    if (result.changes === 0) {
      return errorResponse('Webhook not found', 404);
    }

    return jsonResponse({ message: 'Webhook deleted successfully' });
  } catch (error) {
    console.error('Error deleting webhook:', error);
    return errorResponse('Failed to delete webhook', 500);
  }
});

export default app;
