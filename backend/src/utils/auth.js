// CORS headers (inlined from cors.js)
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
};

// 使用 PBKDF2 进行密码哈希（更安全的算法）
export async function hashPassword(password, salt = null) {
  const encoder = new TextEncoder();

  // 如果没有提供盐值，生成一个新的
  if (!salt) {
    salt = crypto.getRandomValues(new Uint8Array(16));
  } else if (typeof salt === 'string') {
    // 将十六进制字符串转换为 Uint8Array
    salt = new Uint8Array(salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  }

  // 导入密码作为密钥材料
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // 使用 PBKDF2 派生密钥
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000, // 10万次迭代
      hash: 'SHA-256'
    },
    keyMaterial,
    256 // 256位输出
  );

  const hashArray = Array.from(new Uint8Array(derivedBits));
  const saltArray = Array.from(new Uint8Array(salt));

  // 返回格式：salt$hash （都是十六进制字符串）
  const saltHex = saltArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  return `${saltHex}$${hashHex}`;
}

// 验证密码
export async function verifyPassword(password, hashedPassword) {
  try {
    // 检查是否是新格式（salt$hash）
    if (hashedPassword.includes('$')) {
      // 分离盐值和哈希
      const [saltHex, hashHex] = hashedPassword.split('$');

      if (!saltHex || !hashHex) {
        return false;
      }

      // 使用相同的盐值重新哈希
      const newHash = await hashPassword(password, saltHex);

      // 比较哈希值
      return newHash === hashedPassword;
    } else {
      // 旧格式（SHA-256，无盐值）- 用于向后兼容
      const encoder = new TextEncoder();
      const data = encoder.encode(password);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const oldHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      return oldHash === hashedPassword;
    }
  } catch (error) {
    console.error('Error verifying password:', error);
    return false;
  }
}

// 检查密码是否需要升级
export function needsPasswordUpgrade(hashedPassword) {
  return !hashedPassword.includes('$');
}

// 升级旧密码哈希到新格式
export async function upgradePasswordHash(db, userId, newHash) {
  try {
    const stmt = db.prepare(`
      UPDATE users
      SET password_hash = ?, updated_ts = ?
      WHERE id = ?
    `);

    const now = Math.floor(Date.now() / 1000);
    await stmt.bind(newHash, now, userId).run();
    return true;
  } catch (error) {
    console.error('Error upgrading password hash:', error);
    return false;
  }
}

// 生成安全的会话令牌
export function generateSessionToken() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  const tokenArray = Array.from(randomBytes);
  return tokenArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 创建会话
export async function createSession(db, userId, ipAddress = null, userAgent = null) {
  try {
    const token = generateSessionToken();
    const now = Math.floor(Date.now() / 1000);
    const expiresTs = now + (30 * 24 * 60 * 60); // 30天后过期

    const stmt = db.prepare(`
      INSERT INTO sessions (user_id, token, created_ts, expires_ts, last_active_ts, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(userId, token, now, expiresTs, now, ipAddress, userAgent).run();

    return token;
  } catch (error) {
    console.error('Error creating session:', error);
    return null;
  }
}

// 验证会话
export async function validateSession(db, token) {
  try {
    const now = Math.floor(Date.now() / 1000);

    // 查找会话并检查是否过期
    const stmt = db.prepare(`
      SELECT s.id, s.user_id, s.expires_ts, u.username, u.nickname, u.email, u.avatar_url, u.is_admin, u.role
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.token = ? AND s.expires_ts > ?
    `);

    const session = await stmt.bind(token, now).first();

    if (!session) {
      return null;
    }

    // 更新最后活跃时间
    const updateStmt = db.prepare(`
      UPDATE sessions
      SET last_active_ts = ?
      WHERE id = ?
    `);

    await updateStmt.bind(now, session.id).run();

    return {
      id: session.user_id,
      username: session.username,
      nickname: session.nickname,
      email: session.email,
      avatarUrl: session.avatar_url,
      isAdmin: Boolean(session.is_admin),
      is_admin: Boolean(session.is_admin),
      role: session.role || (session.is_admin ? 'admin' : 'user')
    };
  } catch (error) {
    console.error('Error validating session:', error);
    return null;
  }
}

// 删除会话（登出）
export async function deleteSession(db, token) {
  try {
    const stmt = db.prepare('DELETE FROM sessions WHERE token = ?');
    await stmt.bind(token).run();
    return true;
  } catch (error) {
    console.error('Error deleting session:', error);
    return false;
  }
}

// 清理过期会话
export async function cleanupExpiredSessions(db) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const stmt = db.prepare('DELETE FROM sessions WHERE expires_ts < ?');
    await stmt.bind(now).run();
  } catch (error) {
    console.error('Error cleaning up expired sessions:', error);
  }
}

// 生成随机密码
export function generateSecurePassword(length = 16) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  const randomBytes = crypto.getRandomValues(new Uint8Array(length));
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset[randomBytes[i] % charset.length];
  }
  return password;
}

// 获取或创建默认管理员用户
export async function ensureDefaultUser(db) {
  try {
    // 检查是否已有用户
    const userCheck = await db.prepare('SELECT COUNT(*) as count FROM users').first();

    if (userCheck.count === 0) {
      // 生成安全的随机密码
      const randomPassword = generateSecurePassword(16);
      const passwordHash = await hashPassword(randomPassword);

      // 创建第一个用户（管理员）
      const userStmt = db.prepare(`
        INSERT INTO users (username, nickname, password_hash, is_admin)
        VALUES (?, ?, ?, 1)
      `);
      const userResult = await userStmt.bind('admin', '管理员', passwordHash).run();

      // 记录密码到日志 - 仅在首次创建时显示
      console.log('='.repeat(60));
      console.log('⚠️  IMPORTANT: Default admin user created');
      console.log('Username: admin');
      console.log(`Password: ${randomPassword}`);
      console.log('Please change this password immediately after first login!');
      console.log('='.repeat(60));

      return userResult.meta.last_row_id;
    } else {
      // 返回第一个用户的ID
      const firstUser = await db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').first();
      return firstUser?.id || 1;
    }
  } catch (error) {
    console.error('Error ensuring default user:', error);
    return 1; // 回退到ID 1
  }
}

// TOKEN认证中间件
export async function requireAuth(c) {
  // 支持 Hono Context 对象和传统 Request 对象
  const isHonoContext = typeof c.req !== 'undefined';

  let authHeader, token, db, env;

  if (isHonoContext) {
    // Hono Context
    authHeader = c.req.header('Authorization');
    token = authHeader?.replace('Bearer ', '') ||
            c.req.header('X-Token') ||
            c.req.query('token');
    db = c.env.DB;
    env = c.env;
  } else {
    // 传统 Request 对象 (向后兼容)
    authHeader = c.headers.get('Authorization');
    token = authHeader?.replace('Bearer ', '') ||
            c.headers.get('X-Token') ||
            new URL(c.url).searchParams.get('token');
    db = c.env.DB;
    env = c.env;
  }

  if (!token) {
    return jsonResponse({
      error: 'Unauthorized',
      message: 'Valid token required'
    }, 401);
  }

  // 1. 优先尝试验证 JWT Token（格式：eyJ开头的Base64字符串）
  if (token.startsWith('eyJ')) {
    try {
      const { verifyJWT, getJWTSecret } = await import('./jwt.js');
      const jwtSecret = getJWTSecret(env);
      const payload = await verifyJWT(token, jwtSecret);

      if (payload && db) {
        // JWT 验证成功，从数据库获取最新的用户信息（包括头像、昵称等动态数据）
        try {
          const userStmt = db.prepare(`
            SELECT id, username, nickname, email, avatar_url, is_admin, role
            FROM users
            WHERE id = ?
          `);
          const dbUser = await userStmt.bind(payload.id).first();

          if (dbUser) {
            const user = {
              id: dbUser.id,
              username: dbUser.username,
              nickname: dbUser.nickname,
              email: dbUser.email || '',
              avatarUrl: dbUser.avatar_url || '',
              isAdmin: Boolean(dbUser.is_admin) || ['host', 'admin'].includes(dbUser.role),
              is_admin: Boolean(dbUser.is_admin) || ['host', 'admin'].includes(dbUser.role),
              role: dbUser.role || (dbUser.is_admin ? 'admin' : 'user')
            };

            // 将用户信息附加到对象上
            if (isHonoContext) {
              c.set('user', user);
            } else {
              c.user = user;
            }
            return null; // 认证通过
          }
        } catch (dbError) {
          console.error('Error fetching user from database:', dbError);
          // 如果数据库查询失败，回退到使用JWT中的数据
          const user = {
            id: payload.id,
            username: payload.username,
            nickname: payload.nickname,
            email: payload.email,
            avatarUrl: '',
            isAdmin: payload.role === 1 || payload.role === 2,
            is_admin: payload.role === 1 || payload.role === 2,
            role: payload.role === 1 ? 'host' : (payload.role === 2 ? 'admin' : 'user')
          };

          if (isHonoContext) {
            c.set('user', user);
          } else {
            c.user = user;
          }
          return null;
        }
      }
    } catch (error) {
      console.error('Error validating JWT:', error);
    }
  }

  // 2. 检查是否是会话令牌或Access Token（64位十六进制字符串）
  if (token && /^[0-9a-f]{64}$/.test(token)) {
    if (db) {
      try {
        // 首先尝试作为会话令牌验证
        const user = await validateSession(db, token);

        if (user) {
          // 将用户信息附加到对象上
          if (isHonoContext) {
            c.set('user', user);
          } else {
            c.user = user;
          }
          return null; // 认证通过
        }
      } catch (error) {
        console.error('Error validating user session:', error);
      }

      // 如果不是有效的会话令牌，尝试作为Access Token验证
      try {
        const apiTokenStmt = db.prepare(`
          SELECT at.*, u.id as user_id, u.username, u.nickname, u.email, u.is_admin, u.role
          FROM api_tokens at
          JOIN users u ON at.user_id = u.id
          WHERE at.token = ? AND at.is_active = 1
        `);
        const apiTokenResult = await apiTokenStmt.bind(token).first();

        if (apiTokenResult) {
          // 检查是否过期
          if (apiTokenResult.expires_ts && apiTokenResult.expires_ts < Math.floor(Date.now() / 1000)) {
            // Token已过期
            return jsonResponse({
              error: 'Unauthorized',
              message: 'Access token has expired'
            }, 401);
          }

          // Access Token有效，提取用户信息
          const user = {
            id: apiTokenResult.user_id,
            username: apiTokenResult.username,
            nickname: apiTokenResult.nickname,
            email: apiTokenResult.email,
            isAdmin: Boolean(apiTokenResult.is_admin),
            role: apiTokenResult.role || (apiTokenResult.is_admin ? 'admin' : 'user')
          };

          // 将用户信息附加到对象上
          if (isHonoContext) {
            c.set('user', user);
          } else {
            c.user = user;
          }
          return null; // 认证通过
        }
      } catch (error) {
        console.error('Error validating access token:', error);
      }
    }
  }

  // 3. 最后尝试环境变量中的 TOKEN（向后兼容）
  const expectedToken = env.TOKEN;
  if (expectedToken) {
    if (token === expectedToken) {
      return null; // 认证通过
    }
  }

  // 所有验证都失败，返回未授权
  return jsonResponse({
    error: 'Unauthorized',
    message: 'Valid token required'
  }, 401);
}

// JSON响应辅助函数
export function jsonResponse(data, status = 200) {
  // 确保UTF-8编码正确处理中文字符
  let jsonString;
  try {
    // 使用JSON.stringify并显式处理Unicode字符
    jsonString = JSON.stringify(data, (key, value) => {
      if (typeof value === 'string') {
        // 确保字符串正确编码
        return value;
      }
      return value;
    }, 0);
  } catch (error) {
    console.error('JSON serialization error:', error);
    jsonString = JSON.stringify({ error: 'Serialization failed' });
  }
  
  return new Response(jsonString, {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-cache',
      'Accept-Charset': 'utf-8',
      ...corsHeaders
    }
  });
}

// 错误响应辅助函数
export function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// 管理员权限验证中间件
export async function requireAdmin(c) {
  // 首先验证是否登录
  const authError = await requireAuth(c);
  if (authError) return authError;

  // 检查用户角色
  const user = c.get('user');

  // 检查是否是管理员、host或旧版本的 is_admin 字段
  if (!['admin', 'host'].includes(user.role) && !user.is_admin) {
    return errorResponse('Admin permission required', 403);
  }

  return null;
}

// HOST权限验证中间件
export async function requireHost(c) {
  // 首先验证是否登录
  const authError = await requireAuth(c);
  if (authError) return authError;

  // 检查用户角色
  const user = c.get('user');

  if (user.role !== 'host') {
    return errorResponse('Host permission required', 403);
  }

  return null;
}

// 角色验证辅助函数
export function isValidRole(role) {
  return ['host', 'admin', 'user'].includes(role);
}

// 检查用户是否有权限修改目标角色
export function canModifyRole(currentUserRole, targetRole) {
  const rolePriority = {
    'host': 3,
    'admin': 2,
    'user': 1
  };

  const currentPriority = rolePriority[currentUserRole] || 0;
  const targetPriority = rolePriority[targetRole] || 0;

  // 只有HOST可以修改任何角色
  // ADMIN可以修改USER角色，但不能修改ADMIN或HOST
  return currentUserRole === 'host' || (currentUserRole === 'admin' && targetPriority < 2);
}

// 获取请求体JSON
export async function getRequestBody(request) {
  try {
    const contentType = request.headers.get('Content-Type') || '';
    if (contentType.includes('application/json')) {
      return await request.json();
    }
    return {};
  } catch (error) {
    throw new Error('Invalid JSON in request body');
  }
}