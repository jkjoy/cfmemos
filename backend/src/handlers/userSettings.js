import { Hono } from 'hono';
import {
  requireAuth,
  jsonResponse,
  errorResponse
} from '../utils/auth';

const app = new Hono();

// 获取当前用户的设置
app.get('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');

    // 查询用户设置
    const stmt = db.prepare(`
      SELECT locale, appearance, memo_visibility, telegram_user_id
      FROM user_settings
      WHERE user_id = ?
    `);

    let setting = await stmt.bind(currentUser.id).first();

    // 如果用户还没有设置记录,创建默认设置
    if (!setting) {
      const createStmt = db.prepare(`
        INSERT INTO user_settings (user_id, locale, appearance, memo_visibility, telegram_user_id)
        VALUES (?, ?, ?, ?, ?)
      `);

      await createStmt.bind(
        currentUser.id,
        'en',
        'auto',
        'PRIVATE',
        ''
      ).run();

      setting = {
        locale: 'en',
        appearance: 'auto',
        memo_visibility: 'PRIVATE',
        telegram_user_id: ''
      };
    }

    return jsonResponse({
      locale: setting.locale,
      appearance: setting.appearance,
      memoVisibility: setting.memo_visibility,
      telegramUserId: setting.telegram_user_id || ''
    });
  } catch (error) {
    console.error('Error fetching user settings:', error);
    return errorResponse('Failed to fetch user settings', 500);
  }
});

// 更新当前用户的设置
app.post('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');
    const body = await c.req.json();

    console.log('Updating user settings with body:', body);
    console.log('Current user:', currentUser);

    // 验证设置值
    const locale = body.locale !== undefined ? body.locale : 'en';
    const appearance = body.appearance !== undefined ? body.appearance : 'auto';
    const memoVisibility = body.memoVisibility !== undefined ? body.memoVisibility : 'PRIVATE';
    const telegramUserId = body.telegramUserId !== undefined ? body.telegramUserId : '';

    console.log('Parsed values:', { locale, appearance, memoVisibility, telegramUserId });

    // 验证 appearance 值
    const validAppearances = ['auto', 'light', 'dark'];
    if (!validAppearances.includes(appearance)) {
      return errorResponse('Invalid appearance value. Must be: auto, light, or dark', 400);
    }

    // 验证 memoVisibility 值
    const validVisibilities = ['PUBLIC', 'PROTECTED', 'PRIVATE'];
    if (!validVisibilities.includes(memoVisibility)) {
      return errorResponse('Invalid memoVisibility value. Must be: PUBLIC, PROTECTED, or PRIVATE', 400);
    }

    // 检查用户设置是否存在
    const checkStmt = db.prepare('SELECT id FROM user_settings WHERE user_id = ?');
    const existingSetting = await checkStmt.bind(currentUser.id).first();

    console.log('Existing setting:', existingSetting);

    let result;
    if (existingSetting) {
      // 更新现有设置
      const updateStmt = db.prepare(`
        UPDATE user_settings
        SET locale = ?, appearance = ?, memo_visibility = ?, telegram_user_id = ?, updated_ts = ?
        WHERE user_id = ?
      `);

      result = await updateStmt.bind(
        locale,
        appearance,
        memoVisibility,
        telegramUserId,
        Math.floor(Date.now() / 1000),
        currentUser.id
      ).run();
    } else {
      // 创建新设置
      const insertStmt = db.prepare(`
        INSERT INTO user_settings (user_id, locale, appearance, memo_visibility, telegram_user_id)
        VALUES (?, ?, ?, ?, ?)
      `);

      result = await insertStmt.bind(
        currentUser.id,
        locale,
        appearance,
        memoVisibility,
        telegramUserId
      ).run();
    }

    console.log('Update/Insert result:', result);

    if (result.changes === 0 && existingSetting) {
      return errorResponse('Failed to update user settings', 500);
    }

    return jsonResponse({
      locale,
      appearance,
      memoVisibility,
      telegramUserId,
      message: 'User settings updated successfully'
    });
  } catch (error) {
    console.error('Error updating user settings:', error);
    console.error('Error stack:', error.stack);
    return errorResponse('Failed to update user settings', 500);
  }
});

export default app;
