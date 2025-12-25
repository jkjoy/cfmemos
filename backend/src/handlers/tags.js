import { Hono } from 'hono';
import { requireAuth, jsonResponse, errorResponse } from '../utils/auth';

const app = new Hono();

/**
 * GET /api/v1/tag - 列出所有标签
 * 参考 Memos: GET /api/v1/tag
 */
app.get('/', async (c) => {
  // 获取当前用户（如果已登录）
  const token = c.req.header('Authorization')?.replace('Bearer ', '') ||
                c.req.header('X-Token') ||
                c.req.query('token');
  let currentUser = null;

  if (token) {
    try {
      // 优先尝试JWT验证
      if (token.startsWith('eyJ')) {
        const { verifyJWT, getJWTSecret } = await import('../utils/jwt.js');
        const jwtSecret = getJWTSecret(c.env);
        const payload = await verifyJWT(token, jwtSecret);

        if (payload) {
          currentUser = { id: payload.id };
        }
      } else {
        // 回退到session token验证
        const { validateSession } = await import('../utils/auth.js');
        const sessionUser = await validateSession(c.env.DB, token);
        if (sessionUser) {
          currentUser = { id: sessionUser.id };
        }
      }
    } catch (e) {
      // 忽略验证错误，继续作为未登录用户
    }
  }

  try {
    const db = c.env.DB;

    let query = `
      SELECT
        t.id,
        t.name,
        t.creator_id as creatorId,
        t.created_ts as createdTs,
        COUNT(DISTINCT mt.memo_id) as memoCount
      FROM tags t
      LEFT JOIN memo_tags mt ON t.id = mt.tag_id
      LEFT JOIN memos m ON mt.memo_id = m.id AND m.row_status = 'NORMAL'
    `;

    const whereConditions = [];
    const bindValues = [];

    // 只返回当前用户创建的标签
    if (currentUser) {
      whereConditions.push('t.creator_id = ?');
      bindValues.push(currentUser.id);
    } else {
      // 未登录用户不返回任何标签
      return jsonResponse([]);
    }

    if (whereConditions.length > 0) {
      query += ' WHERE ' + whereConditions.join(' AND ');
    }

    query += `
      GROUP BY t.id, t.name, t.creator_id, t.created_ts
      ORDER BY memoCount DESC, t.name ASC
    `;

    const stmt = db.prepare(query);
    const { results } = await stmt.bind(...bindValues).all();

    return jsonResponse(results || []);
  } catch (error) {
    console.error('Error fetching tags:', error);
    return errorResponse('Failed to fetch tags', 500);
  }
});

/**
 * POST /api/v1/tag - 创建标签
 * 参考 Memos: POST /api/v1/tag
 *
 * Body:
 * {
 *   "name": "标签名"
 * }
 */
app.post('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const currentUser = c.get('user');

    if (!currentUser) {
      return errorResponse('User information not found', 401);
    }

    if (!body.name || !body.name.trim()) {
      return errorResponse('Tag name is required', 400);
    }

    const tagName = body.name.trim();

    // 检查当前用户是否已有同名标签
    const checkStmt = db.prepare('SELECT id, name, created_ts as createdTs FROM tags WHERE name = ? AND creator_id = ?');
    const existingTag = await checkStmt.bind(tagName, currentUser.id).first();

    if (existingTag) {
      // 标签已存在，返回现有标签
      return jsonResponse(existingTag);
    }

    // 创建新标签，记录创建者
    const insertStmt = db.prepare('INSERT INTO tags (name, creator_id) VALUES (?, ?)');
    const result = await insertStmt.bind(tagName, currentUser.id).run();

    return jsonResponse({
      id: result.meta.last_row_id,
      name: tagName,
      creatorId: currentUser.id,
      createdTs: Math.floor(Date.now() / 1000),
      message: 'Tag created successfully'
    }, 201);
  } catch (error) {
    console.error('Error creating tag:', error);
    return errorResponse('Failed to create tag', 500);
  }
});

/**
 * GET /api/v1/tag/suggestion - 标签建议
 * 参考 Memos: GET /api/v1/tag/suggestion
 *
 * 返回最常用的标签作为建议
 */
app.get('/suggestion', async (c) => {
  try {
    const db = c.env.DB;
    const limit = parseInt(c.req.query('limit')) || 10;

    const stmt = db.prepare(`
      SELECT
        t.id,
        t.name,
        COUNT(DISTINCT mt.memo_id) as memoCount
      FROM tags t
      JOIN memo_tags mt ON t.id = mt.tag_id
      JOIN memos m ON mt.memo_id = m.id
      WHERE m.row_status = 'NORMAL'
      GROUP BY t.id, t.name
      ORDER BY memoCount DESC, t.name ASC
      LIMIT ?
    `);

    const { results } = await stmt.bind(limit).all();

    return jsonResponse(results || []);
  } catch (error) {
    console.error('Error fetching tag suggestions:', error);
    return errorResponse('Failed to fetch tag suggestions', 500);
  }
});

/**
 * POST /api/v1/tag/delete - 删除标签
 * 参考 Memos: POST /api/v1/tag/delete (在Memos中是POST，不是DELETE)
 *
 * Body:
 * {
 *   "name": "标签名"
 * }
 */
app.post('/delete', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const currentUser = c.get('user');

    if (!currentUser) {
      return errorResponse('User information not found', 401);
    }

    if (!body.name) {
      return errorResponse('Tag name is required', 400);
    }

    // 检查标签是否存在且属于当前用户
    const checkStmt = db.prepare('SELECT id, creator_id FROM tags WHERE name = ?');
    const tag = await checkStmt.bind(body.name).first();

    if (!tag) {
      return errorResponse('Tag not found', 404);
    }

    // 权限检查：只有创建者才能删除
    if (tag.creator_id !== currentUser.id) {
      return errorResponse('Permission denied: You can only delete tags you created', 403);
    }

    // 删除标签（会级联删除memo_tags中的关联，因为有ON DELETE CASCADE）
    const deleteStmt = db.prepare('DELETE FROM tags WHERE id = ?');
    const result = await deleteStmt.bind(tag.id).run();

    if (result.changes === 0) {
      return errorResponse('Failed to delete tag', 500);
    }

    return jsonResponse({
      message: 'Tag deleted successfully',
      name: body.name
    });
  } catch (error) {
    console.error('Error deleting tag:', error);
    return errorResponse('Failed to delete tag', 500);
  }
});

/**
 * DELETE /api/v1/tag/:id - 按ID删除标签（额外提供的RESTful方式）
 */
app.delete('/:id', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const tagId = c.req.param('id');
    const currentUser = c.get('user');

    if (!currentUser) {
      return errorResponse('User information not found', 401);
    }

    // 检查标签是否存在且属于当前用户
    const checkStmt = db.prepare('SELECT id, name, creator_id FROM tags WHERE id = ?');
    const tag = await checkStmt.bind(tagId).first();

    if (!tag) {
      return errorResponse('Tag not found', 404);
    }

    // 权限检查：只有创建者才能删除
    if (tag.creator_id !== currentUser.id) {
      return errorResponse('Permission denied: You can only delete tags you created', 403);
    }

    // 删除标签
    const deleteStmt = db.prepare('DELETE FROM tags WHERE id = ?');
    const result = await deleteStmt.bind(tagId).run();

    if (result.changes === 0) {
      return errorResponse('Failed to delete tag', 500);
    }

    return jsonResponse({
      message: 'Tag deleted successfully',
      name: tag.name
    });
  } catch (error) {
    console.error('Error deleting tag:', error);
    return errorResponse('Failed to delete tag', 500);
  }
});

export default app;
