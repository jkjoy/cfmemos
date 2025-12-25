import { Hono } from 'hono';
import { requireAuth, requireAdmin, jsonResponse, errorResponse } from '../utils/auth';

const app = new Hono();

// 获取公开设置（无需权限）
app.get('/public', async (c) => {
  try {
    const db = c.env.DB;

    const stmt = db.prepare(`
      SELECT key, value
      FROM settings
      WHERE key IN ('site_title', 'site_avatar', 'allow_registration')
    `);

    const { results } = await stmt.all();

    const settings = {};
    results.forEach(row => {
      settings[row.key] = row.value;
    });

    return jsonResponse(settings);
  } catch (error) {
    console.error('Error fetching public settings:', error);
    return errorResponse('Failed to fetch settings', 500);
  }
});

// 获取所有设置（需要管理员权限）
app.get('/', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;

    const stmt = db.prepare('SELECT * FROM settings ORDER BY key');
    const { results } = await stmt.all();

    // 将 key 字段映射为 name，以匹配前端期望的格式
    const formattedResults = results.map(setting => ({
      ...setting,
      name: setting.key
    }));

    return jsonResponse(formattedResults);
  } catch (error) {
    console.error('Error fetching settings:', error);
    return errorResponse('Failed to fetch settings', 500);
  }
});

// 更新或创建设置（POST方法 - 用于兼容前端）
app.post('/', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const body = await c.req.json();

    // 支持单个设置对象或设置对象（取决于前端如何调用）
    const name = body.name || body.key;
    const value = body.value;

    if (!name) {
      return errorResponse('Setting name is required', 400);
    }

    // 检查设置是否存在
    const checkStmt = db.prepare('SELECT id FROM settings WHERE key = ?');
    const existing = await checkStmt.bind(name).first();

    let result;
    if (existing) {
      // 更新现有设置
      const updateStmt = db.prepare(`
        UPDATE settings
        SET value = ?, updated_ts = strftime('%s', 'now')
        WHERE key = ?
      `);
      result = await updateStmt.bind(value, name).run();
    } else {
      // 创建新设置
      const insertStmt = db.prepare(`
        INSERT INTO settings (key, value, description)
        VALUES (?, ?, ?)
      `);
      result = await insertStmt.bind(name, value, body.description || '').run();
    }

    return jsonResponse({
      name,
      value,
      message: 'Setting saved successfully'
    });
  } catch (error) {
    console.error('Error saving setting:', error);
    return errorResponse('Failed to save setting', 500);
  }
});

// 更新设置（需要管理员权限）
app.put('/:key', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const key = c.req.param('key');
    const { value } = await c.req.json();

    const stmt = db.prepare(`
      UPDATE settings
      SET value = ?, updated_ts = strftime('%s', 'now')
      WHERE key = ?
    `);

    await stmt.bind(value, key).run();

    return jsonResponse({ message: 'Setting updated successfully', key, value });
  } catch (error) {
    console.error('Error updating setting:', error);
    return errorResponse('Failed to update setting', 500);
  }
});

export default app;
