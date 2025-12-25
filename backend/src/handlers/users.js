import { Hono } from 'hono';
import {
  requireAuth,
  requireAdmin,
  requireHost,
  isValidRole,
  canModifyRole,
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

const app = new Hono();

// 获取用户列表 - 需要权限
app.get('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;

    const stmt = db.prepare(`
      SELECT id, username, nickname, email, avatar_url, created_ts, is_admin, role, row_status
      FROM users
      ORDER BY created_ts ASC
    `);

    const { results } = await stmt.all();

    // 转换字段名：avatar_url -> avatarUrl, row_status -> rowStatus
    const transformedResults = results.map(user => {
      const transformed = {
        ...user,
        avatarUrl: user.avatar_url,
        rowStatus: user.row_status === 0 ? 'NORMAL' : 'ARCHIVED'
      };
      delete transformed.avatar_url;
      delete transformed.row_status;
      return transformed;
    });

    return jsonResponse(transformedResults);
  } catch (error) {
    console.error('Error fetching users:', error);
    return errorResponse('Failed to fetch users', 500);
  }
});

// 创建用户 - 需要管理员权限或开放注册
app.post('/', async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();

    if (!body.username || !body.nickname || !body.password) {
      return errorResponse('Username, nickname and password are required');
    }

    // 检查密码长度
    if (body.password.length < 6) {
      return errorResponse('Password must be at least 6 characters long');
    }

    // 检查是否是第一个用户
    const userCountStmt = db.prepare('SELECT COUNT(*) as count FROM users');
    const userCount = await userCountStmt.first();
    const isFirstUser = userCount.count === 0;

    // 如果不是第一个用户，检查权限或注册是否开放
    if (!isFirstUser) {
      // 检查是否有管理员权限
      const authError = await requireAdmin(c);
      if (authError) {
        // 如果没有管理员权限，检查注册是否开放
        const settingStmt = db.prepare("SELECT value FROM settings WHERE key = 'allow_registration'");
        const setting = await settingStmt.first();
        if (setting && setting.value === 'false') {
          return errorResponse('Registration is currently disabled', 403);
        }
      }
    }

    // 检查用户名是否已存在
    const existingUserStmt = db.prepare('SELECT id FROM users WHERE username = ?');
    const existingUser = await existingUserStmt.bind(body.username).first();

    if (existingUser) {
      return errorResponse('Username already exists');
    }

    // 密码哈希
    const hashedPassword = await hashPassword(body.password);

    // 确定用户角色：第一个用户为host，其他默认为user
    let userRole = isFirstUser ? 'host' : 'user';

    // 如果请求中指定了角色且当前用户有权限，则使用指定角色
    if (body.role && !isFirstUser) {
      const currentUser = c.get('user');
      if (currentUser && canModifyRole(currentUser.role, body.role)) {
        if (isValidRole(body.role)) {
          userRole = body.role;
        } else {
          return errorResponse('Invalid role. Must be host, admin, or user', 400);
        }
      }
    }

    const stmt = db.prepare(`
      INSERT INTO users (username, nickname, password_hash, email, is_admin, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const result = await stmt.bind(
      body.username,
      body.nickname,
      hashedPassword,
      body.email || null,
      ['host', 'admin'].includes(userRole) ? 1 : 0,
      userRole
    ).run();

    return jsonResponse({
      id: result.meta.last_row_id,
      username: body.username,
      nickname: body.nickname,
      email: body.email,
      is_admin: ['host', 'admin'].includes(userRole),
      role: userRole,
      rowStatus: 'NORMAL',
      message: isFirstUser ? 'First user created as host' : 'User created successfully'
    }, 201);
  } catch (error) {
    console.error('Error creating user:', error);
    return errorResponse('Failed to create user', 500);
  }
});

// 用户登录
app.post('/login', async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();

    if (!body.username || !body.password) {
      return errorResponse('Username and password are required');
    }

    // 检查是否禁用密码登录
    const settingStmt = db.prepare("SELECT value FROM settings WHERE key = 'disable-password-login'");
    const setting = await settingStmt.first();
    if (setting && setting.value === 'true') {
      return errorResponse('Password login is disabled. Please use SSO or other authentication methods.', 403);
    }

    // 清理过期会话
    await cleanupExpiredSessions(db);

    // 查找用户
    const stmt = db.prepare(`
      SELECT id, username, nickname, password_hash, email, avatar_url, is_admin, role
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

    // 获取客户端信息
    const ipAddress = c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || null;
    const userAgent = c.req.header('User-Agent') || null;

    // 创建会话
    const sessionToken = await createSession(db, user.id, ipAddress, userAgent);

    if (!sessionToken) {
      return errorResponse('Failed to create session', 500);
    }

    return jsonResponse({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        nickname: user.nickname,
        email: user.email,
        avatarUrl: user.avatar_url,
        is_admin: Boolean(user.is_admin),
        role: user.role || (user.is_admin ? 'admin' : 'user')
      },
      token: sessionToken
    });
  } catch (error) {
    console.error('Error during login:', error);
    return errorResponse('Login failed', 500);
  }
});

// 用户登出
app.post('/logout', async (c) => {
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
    console.error('Error during logout:', error);
    return errorResponse('Logout failed', 500);
  }
});

// 修改密码 - 需要权限
app.put('/:id/password', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');
    const body = await c.req.json();
    
    if (!body.currentPassword || !body.newPassword) {
      return errorResponse('Current password and new password are required');
    }
    
    // 检查新密码长度
    if (body.newPassword.length < 6) {
      return errorResponse('New password must be at least 6 characters long');
    }
    
    // 获取用户当前密码
    const userStmt = db.prepare('SELECT password_hash FROM users WHERE id = ?');
    const user = await userStmt.bind(id).first();
    
    if (!user) {
      return errorResponse('User not found', 404);
    }
    
    // 验证当前密码
    const isValidPassword = await verifyPassword(body.currentPassword, user.password_hash);
    if (!isValidPassword) {
      return errorResponse('Current password is incorrect', 400);
    }
    
    // 生成新密码哈希
    const newHashedPassword = await hashPassword(body.newPassword);
    
    // 更新密码
    const updateStmt = db.prepare(`
      UPDATE users 
      SET password_hash = ?, updated_ts = ?
      WHERE id = ?
    `);
    
    const result = await updateStmt.bind(
      newHashedPassword,
      Math.floor(Date.now() / 1000),
      id
    ).run();
    
    if (result.changes === 0) {
      return errorResponse('Failed to update password', 500);
    }
    
    return jsonResponse({
      message: 'Password updated successfully'
    });
  } catch (error) {
    console.error('Error updating password:', error);
    return errorResponse('Failed to update password', 500);
  }
});

// 更新用户信息 - 需要权限
app.put('/:id', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');
    const body = await c.req.json();
    const currentUser = c.get('user');

    if (body.nickname === undefined && body.email === undefined && body.avatarUrl === undefined && body.role === undefined && body.rowStatus === undefined) {
      return errorResponse('At least nickname, email, avatarUrl, role or rowStatus must be provided');
    }

    // 获取目标用户信息
    const targetUserStmt = db.prepare('SELECT id, role FROM users WHERE id = ?');
    const targetUser = await targetUserStmt.bind(id).first();

    if (!targetUser) {
      return errorResponse('User not found', 404);
    }

    // 构建动态更新SQL
    const updateFields = [];
    const updateValues = [];

    if (body.nickname) {
      updateFields.push('nickname = ?');
      updateValues.push(body.nickname);
    }

    if (body.email !== undefined) {
      updateFields.push('email = ?');
      updateValues.push(body.email || null);
    }

    if (body.avatarUrl !== undefined) {
      updateFields.push('avatar_url = ?');
      updateValues.push(body.avatarUrl || null);
    }

    // 角色更新需要特殊权限检查
    if (body.role !== undefined) {
      // 验证角色是否有效
      if (!isValidRole(body.role)) {
        return errorResponse('Invalid role. Must be host, admin, or user', 400);
      }

      // 检查当前用户是否有权限修改目标用户的角色
      if (!canModifyRole(currentUser.role, body.role)) {
        return errorResponse('Permission denied: Cannot modify this role', 403);
      }

      // 防止修改其他HOST用户
      if (targetUser.role === 'host' && currentUser.role !== 'host') {
        return errorResponse('Permission denied: Cannot modify host user', 403);
      }

      updateFields.push('role = ?');
      updateValues.push(body.role);
      // 同时更新 is_admin 字段以保持兼容性
      updateFields.push('is_admin = ?');
      updateValues.push(['host', 'admin'].includes(body.role) ? 1 : 0);
    }

    // row_status 更新
    if (body.rowStatus !== undefined) {
      const validStatuses = ['NORMAL', 'ARCHIVED'];
      if (!validStatuses.includes(body.rowStatus)) {
        return errorResponse('Invalid rowStatus. Must be NORMAL or ARCHIVED', 400);
      }
      updateFields.push('row_status = ?');
      updateValues.push(body.rowStatus === 'NORMAL' ? 0 : 1);
    }

    updateFields.push('updated_ts = ?');
    updateValues.push(Math.floor(Date.now() / 1000));

    updateValues.push(id);

    const stmt = db.prepare(`
      UPDATE users
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `);

    const result = await stmt.bind(...updateValues).run();

    // 返回更新后的用户信息
    const userStmt = db.prepare('SELECT id, username, nickname, email, avatar_url, is_admin, role, row_status FROM users WHERE id = ?');
    const user = await userStmt.bind(id).first();

    if (!user) {
      return errorResponse('User not found after update', 500);
    }

    // 转换字段名：avatar_url -> avatarUrl, row_status -> rowStatus
    const responseUser = {
      ...user,
      avatarUrl: user.avatar_url,
      rowStatus: user.row_status === 0 ? 'NORMAL' : 'ARCHIVED'
    };
    delete responseUser.avatar_url;
    delete responseUser.row_status;

    return jsonResponse({
      ...responseUser,
      message: 'User updated successfully'
    });
  } catch (error) {
    console.error('Error updating user:', error);
    return errorResponse('Failed to update user', 500);
  }
});

// PATCH endpoint for updating users (same as PUT, for REST compatibility)
app.patch('/:id', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');
    const body = await c.req.json();
    const currentUser = c.get('user');

    console.log('PATCH /user/:id - Request body:', JSON.stringify(body));
    console.log('PATCH /user/:id - User ID:', id);
    console.log('PATCH /user/:id - Current user:', currentUser.id);

    if (body.nickname === undefined && body.email === undefined && body.avatarUrl === undefined && body.role === undefined && body.rowStatus === undefined) {
      return errorResponse('At least nickname, email, avatarUrl, role or rowStatus must be provided');
    }

    // 获取目标用户信息
    const targetUserStmt = db.prepare('SELECT id, role FROM users WHERE id = ?');
    const targetUser = await targetUserStmt.bind(id).first();

    if (!targetUser) {
      return errorResponse('User not found', 404);
    }

    // 构建动态更新SQL
    const updateFields = [];
    const updateValues = [];

    if (body.nickname !== undefined) {
      console.log('Adding nickname to update:', body.nickname);
      updateFields.push('nickname = ?');
      updateValues.push(body.nickname);
    }

    if (body.email !== undefined) {
      console.log('Adding email to update:', body.email);
      updateFields.push('email = ?');
      updateValues.push(body.email || null);
    }

    if (body.avatarUrl !== undefined) {
      console.log('Adding avatarUrl to update:', body.avatarUrl);
      updateFields.push('avatar_url = ?');
      updateValues.push(body.avatarUrl || null);
    }

    // 角色更新需要特殊权限检查
    if (body.role !== undefined) {
      // 验证角色是否有效
      if (!isValidRole(body.role)) {
        return errorResponse('Invalid role. Must be host, admin, or user', 400);
      }

      // 检查当前用户是否有权限修改目标用户的角色
      if (!canModifyRole(currentUser.role, body.role)) {
        return errorResponse('Permission denied: Cannot modify this role', 403);
      }

      // 防止修改其他HOST用户
      if (targetUser.role === 'host' && currentUser.role !== 'host') {
        return errorResponse('Permission denied: Cannot modify host user', 403);
      }

      updateFields.push('role = ?');
      updateValues.push(body.role);
      // 同时更新 is_admin 字段以保持兼容性
      updateFields.push('is_admin = ?');
      updateValues.push(['host', 'admin'].includes(body.role) ? 1 : 0);
    }

    // row_status 更新
    if (body.rowStatus !== undefined) {
      const validStatuses = ['NORMAL', 'ARCHIVED'];
      if (!validStatuses.includes(body.rowStatus)) {
        return errorResponse('Invalid rowStatus. Must be NORMAL or ARCHIVED', 400);
      }
      updateFields.push('row_status = ?');
      updateValues.push(body.rowStatus === 'NORMAL' ? 0 : 1);
    }

    updateFields.push('updated_ts = ?');
    updateValues.push(Math.floor(Date.now() / 1000));

    updateValues.push(id);

    const stmt = db.prepare(`
      UPDATE users
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `);

    const result = await stmt.bind(...updateValues).run();

    // 返回更新后的用户信息
    const userStmt = db.prepare('SELECT id, username, nickname, email, avatar_url, is_admin, role, row_status FROM users WHERE id = ?');
    const user = await userStmt.bind(id).first();

    if (!user) {
      return errorResponse('User not found after update', 500);
    }

    // 转换字段名：avatar_url -> avatarUrl, row_status -> rowStatus
    const responseUser = {
      ...user,
      avatarUrl: user.avatar_url,
      rowStatus: user.row_status === 0 ? 'NORMAL' : 'ARCHIVED'
    };
    delete responseUser.avatar_url;
    delete responseUser.row_status;

    return jsonResponse({
      ...responseUser,
      message: 'User updated successfully'
    });
  } catch (error) {
    console.error('Error updating user:', error);
    return errorResponse('Failed to update user', 500);
  }
});

// 删除用户 - 需要管理员权限
app.delete('/:id', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');
    const currentUser = c.get('user');

    // 检查用户是否存在
    const userStmt = db.prepare('SELECT id, role FROM users WHERE id = ?');
    const user = await userStmt.bind(id).first();

    if (!user) {
      return errorResponse('User not found', 404);
    }

    // 防止删除HOST用户
    if (user.role === 'host') {
      return errorResponse('Cannot delete host user', 403);
    }

    // ADMIN只能删除普通用户，不能删除其他ADMIN
    if (currentUser.role === 'admin' && user.role === 'admin') {
      return errorResponse('Permission denied: Cannot delete other admin users', 403);
    }

    // 删除用户的会话
    const deleteSessionsStmt = db.prepare('DELETE FROM sessions WHERE user_id = ?');
    await deleteSessionsStmt.bind(id).run();

    // 删除用户
    const deleteUserStmt = db.prepare('DELETE FROM users WHERE id = ?');
    const result = await deleteUserStmt.bind(id).run();

    if (result.changes === 0) {
      return errorResponse('Failed to delete user', 500);
    }

    return jsonResponse({
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    return errorResponse('Failed to delete user', 500);
  }
});

export default app;
