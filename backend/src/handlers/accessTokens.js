import { Hono } from 'hono';
import { requireAuth, jsonResponse, errorResponse } from '../utils/auth';
import { generateJWT, getJWTSecret } from '../utils/jwt';

const app = new Hono();

// 获取用户的 Access Tokens
app.get('/:username/access-tokens', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const username = c.req.param('username');
    const currentUser = c.get('user');

    // 只能查看自己的 tokens
    if (currentUser.username !== username) {
      return errorResponse('Forbidden', 403);
    }

    const stmt = db.prepare(`
      SELECT id, name, token, created_ts, expires_ts, is_active
      FROM api_tokens
      WHERE user_id = ? AND is_active = 1
      ORDER BY created_ts DESC
    `);

    const { results } = await stmt.bind(currentUser.id).all();

    // 转换为前端期望的格式
    const accessTokens = results.map(token => ({
      name: `users/${username}/accessTokens/${token.id}`,
      accessToken: token.token,
      description: token.name,
      issuedAt: new Date(token.created_ts * 1000).toISOString(),
      expiresAt: token.expires_ts ? new Date(token.expires_ts * 1000).toISOString() : null,
    }));

    return jsonResponse(accessTokens);
  } catch (error) {
    console.error('Error fetching access tokens:', error);
    return errorResponse('Failed to fetch access tokens', 500);
  }
});

// 创建新的 Access Token
app.post('/:username/access-tokens', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const username = c.req.param('username');
    const currentUser = c.get('user');
    const body = await c.req.json();

    // 只能为自己创建 tokens
    if (currentUser.username !== username) {
      return errorResponse('Forbidden', 403);
    }

    if (!body.description) {
      return errorResponse('Description is required', 400);
    }

    const now = Math.floor(Date.now() / 1000);

    // 计算过期时间（如果提供）
    let expiresTs = null;
    let expiresIn = 100 * 365 * 24 * 60 * 60; // 默认100年（表示永不过期）

    if (body.expiresAt) {
      expiresTs = Math.floor(new Date(body.expiresAt).getTime() / 1000);
      expiresIn = expiresTs - now;
    }

    // 转换角色为数字 (1=HOST, 2=ADMIN, 3=USER)
    const roleMap = { 'host': 1, 'admin': 2, 'user': 3 };
    const roleValue = roleMap[currentUser.role] || 3;

    // 生成 JWT Access Token
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: currentUser.id,
      username: currentUser.username,
      nickname: currentUser.nickname,
      email: currentUser.email || '',
      role: roleValue,
      tokenType: 'access_token',  // 标记为 Access Token
      description: body.description
    }, jwtSecret, expiresIn);

    // 保存到数据库（用于管理和撤销）
    const stmt = db.prepare(`
      INSERT INTO api_tokens (user_id, name, token, created_ts, expires_ts)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = await stmt.bind(
      currentUser.id,
      body.description,
      token,
      now,
      expiresTs
    ).run();

    const tokenId = result.meta.last_row_id;

    // 返回创建的 token
    return jsonResponse({
      name: `users/${username}/accessTokens/${tokenId}`,
      accessToken: token,
      description: body.description,
      issuedAt: new Date(now * 1000).toISOString(),
      expiresAt: expiresTs ? new Date(expiresTs * 1000).toISOString() : null,
    }, 201);
  } catch (error) {
    console.error('Error creating access token:', error);
    return errorResponse('Failed to create access token', 500);
  }
});

// 删除 Access Token
app.delete('/:username/access-tokens/:token', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const username = c.req.param('username');
    const token = c.req.param('token');
    const currentUser = c.get('user');

    // 只能删除自己的 tokens
    if (currentUser.username !== username) {
      return errorResponse('Forbidden', 403);
    }

    // 软删除：设置 is_active = 0
    const stmt = db.prepare(`
      UPDATE api_tokens
      SET is_active = 0
      WHERE user_id = ? AND token = ?
    `);

    await stmt.bind(currentUser.id, token).run();

    return jsonResponse({ message: 'Access token deleted successfully' });
  } catch (error) {
    console.error('Error deleting access token:', error);
    return errorResponse('Failed to delete access token', 500);
  }
});

export default app;
