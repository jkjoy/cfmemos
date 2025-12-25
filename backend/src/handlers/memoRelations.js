import { Hono } from 'hono';
import { requireAuth, jsonResponse, errorResponse } from '../utils/auth';

const app = new Hono();

/**
 * GET /api/v1/memo/:id/relation - 列出memo的所有关系
 * 参考 Memos: GET /api/v1/memo/{memoId}/relation
 */
app.get('/:id/relation', async (c) => {
  try {
    const db = c.env.DB;
    const memoId = c.req.param('id');

    // 检查memo是否存在
    const memoStmt = db.prepare('SELECT id FROM memos WHERE id = ? AND row_status = ?');
    const memo = await memoStmt.bind(memoId, 'NORMAL').first();

    if (!memo) {
      return errorResponse('Memo not found', 404);
    }

    // 获取所有关系
    const stmt = db.prepare(`
      SELECT
        mr.id,
        mr.memo_id as memoId,
        mr.related_memo_id as relatedMemoId,
        mr.type,
        mr.created_ts as createdTs,
        m.content as relatedMemoContent,
        m.creator_id as relatedMemoCreatorId,
        u.username as relatedMemoCreatorUsername,
        u.nickname as relatedMemoCreatorName
      FROM memo_relations mr
      LEFT JOIN memos m ON mr.related_memo_id = m.id
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE mr.memo_id = ?
      ORDER BY mr.created_ts DESC
    `);

    const { results } = await stmt.bind(memoId).all();

    return jsonResponse(results || []);
  } catch (error) {
    console.error('Error fetching memo relations:', error);
    return errorResponse('Failed to fetch memo relations', 500);
  }
});

/**
 * POST /api/v1/memo/:id/relation - 创建memo关系
 * 参考 Memos: POST /api/v1/memo/{memoId}/relation
 *
 * Body:
 * {
 *   "relatedMemoId": 123,
 *   "type": "REFERENCE" | "COMMENT"
 * }
 */
app.post('/:id/relation', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const memoId = c.req.param('id');
    const body = await c.req.json();

    if (!body.relatedMemoId) {
      return errorResponse('relatedMemoId is required', 400);
    }

    if (!body.type || !['REFERENCE', 'COMMENT'].includes(body.type)) {
      return errorResponse('type must be either REFERENCE or COMMENT', 400);
    }

    // 检查两个memo是否都存在
    const checkStmt = db.prepare(`
      SELECT id FROM memos WHERE id IN (?, ?) AND row_status = 'NORMAL'
    `);
    const { results: memos } = await checkStmt.bind(memoId, body.relatedMemoId).all();

    if (memos.length !== 2) {
      return errorResponse('One or both memos not found', 404);
    }

    // 防止自我引用
    if (parseInt(memoId) === parseInt(body.relatedMemoId)) {
      return errorResponse('Cannot create relation to self', 400);
    }

    // 检查关系是否已存在
    const existingStmt = db.prepare(`
      SELECT id FROM memo_relations
      WHERE memo_id = ? AND related_memo_id = ? AND type = ?
    `);
    const existing = await existingStmt.bind(memoId, body.relatedMemoId, body.type).first();

    if (existing) {
      return errorResponse('Relation already exists', 409);
    }

    // 创建关系
    const insertStmt = db.prepare(`
      INSERT INTO memo_relations (memo_id, related_memo_id, type)
      VALUES (?, ?, ?)
    `);

    const result = await insertStmt.bind(memoId, body.relatedMemoId, body.type).run();

    return jsonResponse({
      id: result.meta.last_row_id,
      memoId: parseInt(memoId),
      relatedMemoId: body.relatedMemoId,
      type: body.type,
      message: 'Relation created successfully'
    }, 201);
  } catch (error) {
    console.error('Error creating memo relation:', error);
    return errorResponse('Failed to create memo relation', 500);
  }
});

/**
 * DELETE /api/v1/memo/:id/relation/:relatedId/type/:type - 删除memo关系
 * 参考 Memos: DELETE /api/v1/memo/{memoId}/relation/{relatedMemoId}/type/{type}
 */
app.delete('/:id/relation/:relatedId/type/:type', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const memoId = c.req.param('id');
    const relatedId = c.req.param('relatedId');
    const type = c.req.param('type');

    if (!['REFERENCE', 'COMMENT'].includes(type)) {
      return errorResponse('type must be either REFERENCE or COMMENT', 400);
    }

    // 检查关系是否存在
    const checkStmt = db.prepare(`
      SELECT id FROM memo_relations
      WHERE memo_id = ? AND related_memo_id = ? AND type = ?
    `);
    const relation = await checkStmt.bind(memoId, relatedId, type).first();

    if (!relation) {
      return errorResponse('Relation not found', 404);
    }

    // 删除关系
    const deleteStmt = db.prepare(`
      DELETE FROM memo_relations
      WHERE memo_id = ? AND related_memo_id = ? AND type = ?
    `);

    const result = await deleteStmt.bind(memoId, relatedId, type).run();

    if (result.changes === 0) {
      return errorResponse('Failed to delete relation', 500);
    }

    return jsonResponse({
      message: 'Relation deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting memo relation:', error);
    return errorResponse('Failed to delete memo relation', 500);
  }
});

export default app;
