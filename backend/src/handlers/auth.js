import { Hono } from 'hono';
import {
  jsonResponse,
  errorResponse,
  hashPassword,
  verifyPassword,
  needsPasswordUpgrade,
  upgradePasswordHash,
  createSession,
  deleteSession,
  cleanupExpiredSessions
} from '../utils/auth';
import { generateJWT, getJWTSecret } from '../utils/jwt';

const app = new Hono();

/**
 * POST /api/v1/auth/signin - 用户登录
 * 参考 Memos: POST /api/v1/auth/signin
 */
app.post('/signin', async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();

    if (!body.username || !body.password) {
      return errorResponse('Username and password are required', 400);
    }

    // 清理过期会话
    await cleanupExpiredSessions(db);

    // 查找用户
    const stmt = db.prepare(`
      SELECT id, username, nickname, password_hash, email, is_admin, role
      FROM users
      WHERE username = ?
    `);

    const user = await stmt.bind(body.username).first();

    if (!user) {
      return errorResponse('Invalid username or password', 401);
    }

    // 验证密码
    const isValidPassword = await verifyPassword(body.password, user.password_hash);

    if (!isValidPassword) {
      return errorResponse('Invalid username or password', 401);
    }

    // 检查密码是否需要升级（从旧的 SHA-256 升级到 PBKDF2）
    if (needsPasswordUpgrade(user.password_hash)) {
      console.log(`Upgrading password hash for user ${user.username}`);
      const newHash = await hashPassword(body.password);
      await upgradePasswordHash(db, user.id, newHash);
    }

    // 转换角色字符串为枚举数字 (1=HOST, 2=ADMIN, 3=USER)
    const roleMap = { 'host': 1, 'admin': 2, 'user': 3 };
    const roleValue = roleMap[user.role] || 3;

    // 生成 JWT Token
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: user.id,
      username: user.username,
      nickname: user.nickname,
      email: user.email || '',
      role: roleValue
    }, jwtSecret);

    return jsonResponse({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        name: `users/${user.username}`,
        username: user.username,
        nickname: user.nickname,
        email: user.email || '',
        avatarUrl: '',
        role: roleValue,
        rowStatus: 0
      },
      token: token
    });
  } catch (error) {
    console.error('Error during signin:', error);
    return errorResponse('Login failed', 500);
  }
});

/**
 * POST /api/v1/auth/signup - 用户注册
 * 参考 Memos: POST /api/v1/auth/signup
 */
app.post('/signup', async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();

    if (!body.username || !body.nickname || !body.password) {
      return errorResponse('Username, nickname and password are required', 400);
    }

    // 检查密码长度
    if (body.password.length < 6) {
      return errorResponse('Password must be at least 6 characters long', 400);
    }

    // 检查是否是第一个用户
    const userCountStmt = db.prepare('SELECT COUNT(*) as count FROM users');
    const userCount = await userCountStmt.first();
    const isFirstUser = userCount.count === 0;

    // 如果不是第一个用户，检查注册是否开放
    if (!isFirstUser) {
      const settingStmt = db.prepare("SELECT value FROM settings WHERE key = 'allow_registration'");
      const setting = await settingStmt.first();
      if (setting && setting.value === 'false') {
        return errorResponse('Registration is currently disabled', 403);
      }
    }

    // 检查用户名是否已存在
    const existingUserStmt = db.prepare('SELECT id FROM users WHERE username = ?');
    const existingUser = await existingUserStmt.bind(body.username).first();

    if (existingUser) {
      return errorResponse('Username already exists', 400);
    }

    // 密码哈希
    const hashedPassword = await hashPassword(body.password);

    // 确定用户角色：第一个用户为 host，其他为 user
    const userRole = isFirstUser ? 'host' : 'user';

    const stmt = db.prepare(`
      INSERT INTO users (username, nickname, password_hash, email, is_admin, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const result = await stmt.bind(
      body.username,
      body.nickname,
      hashedPassword,
      body.email || null,
      isFirstUser ? 1 : 0,
      userRole
    ).run();

    return jsonResponse({
      id: result.meta.last_row_id,
      username: body.username,
      nickname: body.nickname,
      email: body.email,
      role: userRole,
      message: isFirstUser ? 'First user created as host' : 'User created successfully'
    }, 201);
  } catch (error) {
    console.error('Error during signup:', error);
    return errorResponse('Registration failed', 500);
  }
});

/**
 * POST /api/v1/auth/signout - 用户登出
 * 参考 Memos: POST /api/v1/auth/signout
 */
app.post('/signout', async (c) => {
  try {
    const db = c.env.DB;
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.replace('Bearer ', '') ||
                  c.req.header('X-Token') ||
                  c.req.query('token');

    if (token && /^[0-9a-f]{64}$/.test(token)) {
      await deleteSession(db, token);
    }

    return jsonResponse({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Error during signout:', error);
    return errorResponse('Logout failed', 500);
  }
});

/**
 * GET /api/v1/auth/status - 获取认证状态
 * 参考 Memos v2: POST /api/v2/auth/status
 */
app.get('/status', async (c) => {
  try {
    const db = c.env.DB;
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.replace('Bearer ', '') ||
                  c.req.header('X-Token') ||
                  c.req.query('token');

    if (!token) {
      return jsonResponse({
        authenticated: false,
        user: null
      });
    }

    // 验证 JWT Token
    const { verifyJWT } = await import('../utils/jwt.js');
    const jwtSecret = getJWTSecret(c.env);
    const payload = await verifyJWT(token, jwtSecret);

    if (!payload) {
      return jsonResponse({
        authenticated: false,
        user: null
      });
    }

    // 从数据库获取最新的用户信息（包括头像、昵称等）
    const userStmt = db.prepare(`
      SELECT id, username, nickname, email, avatar_url, is_admin, role
      FROM users
      WHERE id = ?
    `);
    const dbUser = await userStmt.bind(payload.id).first();

    if (!dbUser) {
      return jsonResponse({
        authenticated: false,
        user: null
      });
    }

    // 转换角色字符串为枚举数字 (1=HOST, 2=ADMIN, 3=USER)
    const roleMap = { 'host': 1, 'admin': 2, 'user': 3 };
    const roleValue = roleMap[dbUser.role] || 3;

    return jsonResponse({
      authenticated: true,
      user: {
        id: dbUser.id,
        name: `users/${dbUser.username}`,
        username: dbUser.username,
        nickname: dbUser.nickname,
        email: dbUser.email || '',
        avatarUrl: dbUser.avatar_url || '',
        role: roleValue,
        rowStatus: 0
      }
    });
  } catch (error) {
    console.error('Error checking auth status:', error);
    return jsonResponse({
      authenticated: false,
      user: null
    });
  }
});

/**
 * POST /api/v1/auth/signin/sso - SSO登录
 * 参考 Memos: POST /api/v1/auth/signin/sso
 *
 * Body: { identityProviderId, code, redirectUri }
 */
app.post('/signin/sso', async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();

    console.log('=== SSO Login Request ===');
    console.log('Request body:', JSON.stringify(body));

    if (!body.identityProviderId || !body.code || !body.redirectUri) {
      console.error('Missing required parameters');
      return errorResponse('identityProviderId, code and redirectUri are required', 400);
    }

    // 获取identity provider配置
    const idpStmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config
      FROM identity_providers
      WHERE id = ?
    `);
    const idp = await idpStmt.bind(body.identityProviderId).first();

    if (!idp) {
      console.error('Identity provider not found:', body.identityProviderId);
      return errorResponse('Identity provider not found', 404);
    }

    console.log('IDP found:', idp.name, 'Type:', idp.type);

    let config;
    try {
      config = JSON.parse(idp.config);
      console.log('Config parsed successfully');
    } catch (e) {
      console.error('Failed to parse IDP config:', e);
      return errorResponse('Invalid identity provider configuration', 500);
    }

    // 提取实际的OAuth2配置（兼容前端的嵌套格式）
    let oauth2Config = config;
    if (config.oauth2Config) {
      oauth2Config = config.oauth2Config;
      console.log('Using nested oauth2Config');
    }

    // OAuth2 流程：用code换取access_token
    let tokenResponse;
    try {
      const tokenUrl = getTokenUrl(idp.type, oauth2Config);
      console.log('Exchanging code for token at:', tokenUrl);
      console.log('IDP type:', idp.type);
      console.log('Config has tokenUrl:', !!oauth2Config.tokenUrl);

      const tokenParams = new URLSearchParams({
        client_id: oauth2Config.clientId,
        client_secret: oauth2Config.clientSecret,
        code: body.code,
        redirect_uri: body.redirectUri,
        grant_type: 'authorization_code'
      });

      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: tokenParams
      });

      console.log('Token exchange response status:', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Token exchange failed with status:', response.status);
        console.error('Error response:', errorText);
        return errorResponse('Failed to exchange authorization code', 401);
      }

      tokenResponse = await response.json();
      console.log('Token response received:', JSON.stringify(tokenResponse));
      console.log('Token response received, has access_token:', !!tokenResponse.access_token);
    } catch (error) {
      console.error('Error exchanging code for token:', error);
      console.error('Error stack:', error.stack);
      return errorResponse('Failed to authenticate with identity provider', 500);
    }

    // 获取用户信息
    let userInfo;
    try {
      const userInfoUrl = getUserInfoUrl(idp.type, oauth2Config);
      console.log('Fetching user info from:', userInfoUrl);
      console.log('Using access token:', tokenResponse.access_token?.substring(0, 20) + '...');

      const userInfoResponse = await fetch(userInfoUrl, {
        headers: {
          'Authorization': `Bearer ${tokenResponse.access_token}`,
          'Accept': 'application/json',
          'User-Agent': 'Memos-SSO-Client/1.0'  // GitHub API 要求 User-Agent
        }
      });

      console.log('User info response status:', userInfoResponse.status);

      if (!userInfoResponse.ok) {
        const errorText = await userInfoResponse.text();
        console.error('User info request failed with status:', userInfoResponse.status);
        console.error('Error response:', errorText);
        // 返回详细的错误信息
        return errorResponse(`Failed to get user information: ${userInfoResponse.status} - ${errorText.substring(0, 200)}`, 401);
      }

      userInfo = await userInfoResponse.json();
      console.log('User info received:', JSON.stringify(userInfo).substring(0, 200));

      // GitHub特殊处理：如果email为空，尝试从/user/emails获取
      if (idp.type === 'OAUTH2' && (!userInfo.email || userInfo.email === null)) {
        console.log('Email not found in user info, checking if GitHub...');
        // 检查是否是GitHub（通过userInfoUrl判断）
        if (userInfoUrl.includes('api.github.com')) {
          console.log('Detected GitHub, fetching emails from /user/emails');
          try {
            const emailsResponse = await fetch('https://api.github.com/user/emails', {
              headers: {
                'Authorization': `Bearer ${tokenResponse.access_token}`,
                'Accept': 'application/json',
                'User-Agent': 'Memos-SSO-Client/1.0'  // GitHub API 要求 User-Agent
              }
            });
            console.log('GitHub emails response status:', emailsResponse.status);
            if (emailsResponse.ok) {
              const emails = await emailsResponse.json();
              console.log('GitHub emails response:', JSON.stringify(emails));
              // 查找primary email
              const primaryEmail = emails.find(e => e.primary);
              if (primaryEmail) {
                userInfo.email = primaryEmail.email;
                console.log('Using primary email:', userInfo.email);
              } else if (emails.length > 0) {
                userInfo.email = emails[0].email;
                console.log('Using first email:', userInfo.email);
              }
            } else {
              const emailError = await emailsResponse.text();
              console.error('Failed to fetch GitHub emails:', emailsResponse.status, emailError);
            }
          } catch (emailError) {
            console.error('Failed to fetch GitHub emails:', emailError);
            // 继续处理，可能没有email权限
          }
        }
      }
    } catch (error) {
      console.error('Error getting user info:', error);
      console.error('Error stack:', error.stack);
      // 返回详细的错误信息
      return errorResponse(`Failed to get user information from identity provider: ${error.message}`, 500);
    }

    // 提取标准化的用户信息
    const email = getUserEmail(idp.type, userInfo, oauth2Config);
    const username = getUserUsername(idp.type, userInfo, oauth2Config);
    const nickname = getUserNickname(idp.type, userInfo, oauth2Config);

    if (!username) {
      return errorResponse('Username is required for SSO login', 400);
    }

    // 检查 identifier_filter（email域名过滤）
    if (idp.identifier_filter && email) {
      const allowedDomains = idp.identifier_filter.split(',').map(d => d.trim());
      const emailDomain = email.split('@')[1];
      if (!allowedDomains.includes(emailDomain)) {
        return errorResponse(`Email domain ${emailDomain} is not allowed for this identity provider`, 403);
      }
    }

    // 查找或创建用户（根据 username）
    let user;
    const userStmt = db.prepare('SELECT * FROM users WHERE username = ?');
    user = await userStmt.bind(username).first();

    if (!user) {
      // 创建新用户
      const hashedPassword = await hashPassword(Math.random().toString(36)); // 随机密码，SSO用户不使用

      const insertStmt = db.prepare(`
        INSERT INTO users (username, nickname, email, password_hash, is_admin, role)
        VALUES (?, ?, ?, ?, 0, 'user')
      `);

      const result = await insertStmt.bind(
        username,
        nickname || username,
        email || null,
        hashedPassword
      ).run();

      // 重新查询创建的用户
      user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(result.meta.last_row_id).first();
      console.log('Created new user via SSO:', username);
    } else {
      console.log('Found existing user via SSO:', username);
    }

    // 转换角色字符串为枚举数字
    const roleMap = { 'host': 1, 'admin': 2, 'user': 3 };
    const roleValue = roleMap[user.role] || 3;

    // 生成 JWT Token
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: user.id,
      username: user.username,
      nickname: user.nickname,
      email: user.email || '',
      role: roleValue
    }, jwtSecret);

    return jsonResponse({
      success: true,
      message: 'SSO login successful',
      user: {
        id: user.id,
        name: `users/${user.username}`,
        username: user.username,
        nickname: user.nickname,
        email: user.email || '',
        avatarUrl: user.avatar_url || '',
        role: roleValue,
        rowStatus: 0
      },
      token: token
    });
  } catch (error) {
    console.error('Error during SSO signin:', error);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    // 返回更详细的错误信息以便调试
    return errorResponse(`SSO login failed: ${error.message}`, 500);
  }
});

// Helper functions for OAuth2 providers
function getTokenUrl(type, config) {
  // 对于 OAUTH2 类型，直接使用config中的tokenUrl
  if (type === 'OAUTH2') {
    return config.tokenUrl;
  }

  const urls = {
    'google': 'https://oauth2.googleapis.com/token',
    'github': 'https://github.com/login/oauth/access_token',
    'gitlab': `${config.instanceUrl || 'https://gitlab.com'}/oauth/token`,
    'oidc': config.tokenUrl
  };
  return urls[type] || config.tokenUrl;
}

function getUserInfoUrl(type, config) {
  // 对于 OAUTH2 类型，直接使用config中的userInfoUrl
  if (type === 'OAUTH2') {
    return config.userInfoUrl;
  }

  const urls = {
    'google': 'https://www.googleapis.com/oauth2/v2/userinfo',
    'github': 'https://api.github.com/user',
    'gitlab': `${config.instanceUrl || 'https://gitlab.com'}/api/v4/user`,
    'oidc': config.userInfoUrl
  };
  return urls[type] || config.userInfoUrl;
}

function getUserEmail(type, userInfo, config) {
  // 优先使用fieldMapping中配置的email字段
  if (config.fieldMapping && config.fieldMapping.email) {
    return userInfo[config.fieldMapping.email];
  }

  // 对于 OAUTH2 类型，默认使用 email 字段
  if (type === 'OAUTH2') {
    return userInfo.email;
  }

  // 回退到默认逻辑
  if (type === 'google') return userInfo.email;
  if (type === 'github') return userInfo.email;
  if (type === 'gitlab') return userInfo.email;
  return userInfo.email; // OIDC standard
}

function getUserUsername(type, userInfo, config) {
  // 优先使用fieldMapping中配置的identifier字段
  if (config.fieldMapping && config.fieldMapping.identifier) {
    return userInfo[config.fieldMapping.identifier];
  }

  // 对于 OAUTH2 类型，尝试多种可能的字段
  if (type === 'OAUTH2') {
    return userInfo.login || userInfo.username || userInfo.preferred_username || userInfo.email?.split('@')[0];
  }

  // 回退到默认逻辑
  if (type === 'google') return userInfo.email?.split('@')[0];
  if (type === 'github') return userInfo.login;
  if (type === 'gitlab') return userInfo.username;
  return userInfo.preferred_username || userInfo.email?.split('@')[0];
}

function getUserNickname(type, userInfo, config) {
  // 优先使用fieldMapping中配置的displayName字段
  if (config.fieldMapping && config.fieldMapping.displayName) {
    return userInfo[config.fieldMapping.displayName];
  }

  // 对于 OAUTH2 类型，尝试多种可能的字段
  if (type === 'OAUTH2') {
    return userInfo.name || userInfo.display_name || userInfo.nickname || userInfo.login || userInfo.username;
  }

  // 回退到默认逻辑
  if (type === 'google') return userInfo.name;
  if (type === 'github') return userInfo.name || userInfo.login;
  if (type === 'gitlab') return userInfo.name;
  return userInfo.name || userInfo.preferred_username;
}

export default app;
