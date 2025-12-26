import { Hono } from 'hono';
import {
  requireAuth,
  requireAdmin,
  jsonResponse,
  errorResponse
} from '../utils/auth';

const app = new Hono();

// 获取身份提供商列表 - 需要管理员权限
app.get('/', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;

    const stmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config, created_ts, updated_ts
      FROM identity_providers
      ORDER BY created_ts ASC
    `);

    const { results } = await stmt.all();

    // 隐藏敏感信息（client_secret）
    const safeResults = results.map(idp => {
      try {
        const config = JSON.parse(idp.config);
        // 删除敏感字段
        if (config.clientSecret) {
          config.clientSecret = '***';
        }
        return {
          ...idp,
          identifierFilter: idp.identifier_filter,
          config
        };
      } catch (e) {
        return {
          ...idp,
          identifierFilter: idp.identifier_filter,
          config: {}
        };
      }
    });

    return jsonResponse(safeResults);
  } catch (error) {
    console.error('Error fetching identity providers:', error);
    return errorResponse('Failed to fetch identity providers', 500);
  }
});

// 获取单个身份提供商 - 需要管理员权限
app.get('/:id', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');

    const stmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config, created_ts, updated_ts
      FROM identity_providers
      WHERE id = ?
    `);

    const idp = await stmt.bind(id).first();

    if (!idp) {
      return errorResponse('Identity provider not found', 404);
    }

    try {
      const config = JSON.parse(idp.config);
      // 删除敏感字段
      if (config.clientSecret) {
        config.clientSecret = '***';
      }
      return jsonResponse({
        ...idp,
        identifierFilter: idp.identifier_filter,
        config
      });
    } catch (e) {
      return jsonResponse({
        ...idp,
        identifierFilter: idp.identifier_filter,
        config: {}
      });
    }
  } catch (error) {
    console.error('Error fetching identity provider:', error);
    return errorResponse('Failed to fetch identity provider', 500);
  }
});

// 创建身份提供商 - 需要管理员权限
app.post('/', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const body = await c.req.json();

    if (!body.name || !body.type) {
      return errorResponse('Name and type are required');
    }

    // 验证类型 - 兼容前端的 "OAUTH2" 格式
    const validTypes = ['google', 'github', 'gitlab', 'oidc', 'OAUTH2'];
    if (!validTypes.includes(body.type)) {
      return errorResponse(`Invalid type. Must be one of: ${validTypes.join(', ')}`);
    }

    // 验证配置
    if (!body.config || typeof body.config !== 'object') {
      return errorResponse('Config is required and must be an object');
    }

    // 提取实际的配置对象（兼容前端的嵌套格式）
    let actualConfig = body.config;
    if (body.config.oauth2Config) {
      // 前端格式：{ oauth2Config: { clientId, clientSecret, ... } }
      actualConfig = body.config.oauth2Config;
    }

    // 基本配置验证
    const requiredConfigFields = ['clientId', 'clientSecret'];
    for (const field of requiredConfigFields) {
      if (!actualConfig[field]) {
        return errorResponse(`Config must include ${field}`);
      }
    }

    // 保存时使用原始格式（保持前端格式不变）
    const stmt = db.prepare(`
      INSERT INTO identity_providers (name, type, identifier_filter, config)
      VALUES (?, ?, ?, ?)
    `);

    const result = await stmt.bind(
      body.name,
      body.type,
      body.identifierFilter || '',
      JSON.stringify(body.config)
    ).run();

    return jsonResponse({
      id: result.meta.last_row_id,
      name: body.name,
      type: body.type,
      identifierFilter: body.identifierFilter || '',
      message: 'Identity provider created successfully'
    }, 201);
  } catch (error) {
    console.error('Error creating identity provider:', error);
    return errorResponse('Failed to create identity provider', 500);
  }
});

// 更新身份提供商 - 需要管理员权限
app.patch('/:id', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');
    const body = await c.req.json();

    // 检查是否存在
    const checkStmt = db.prepare('SELECT id FROM identity_providers WHERE id = ?');
    const exists = await checkStmt.bind(id).first();

    if (!exists) {
      return errorResponse('Identity provider not found', 404);
    }

    // 构建动态更新SQL
    const updateFields = [];
    const updateValues = [];

    if (body.name !== undefined) {
      updateFields.push('name = ?');
      updateValues.push(body.name);
    }

    if (body.type !== undefined) {
      const validTypes = ['google', 'github', 'gitlab', 'oidc', 'OAUTH2'];
      if (!validTypes.includes(body.type)) {
        return errorResponse(`Invalid type. Must be one of: ${validTypes.join(', ')}`);
      }
      updateFields.push('type = ?');
      updateValues.push(body.type);
    }

    if (body.identifierFilter !== undefined) {
      updateFields.push('identifier_filter = ?');
      updateValues.push(body.identifierFilter);
    }

    if (body.config !== undefined) {
      if (typeof body.config !== 'object') {
        return errorResponse('Config must be an object');
      }

      // 提取实际的配置对象（兼容前端的嵌套格式）
      let actualConfig = body.config;
      if (body.config.oauth2Config) {
        actualConfig = body.config.oauth2Config;
      }

      // 验证必填字段（如果提供了clientSecret）
      if (actualConfig.clientSecret && !actualConfig.clientId) {
        return errorResponse('Config must include clientId when clientSecret is provided');
      }

      updateFields.push('config = ?');
      updateValues.push(JSON.stringify(body.config));
    }

    if (updateFields.length === 0) {
      return errorResponse('No fields to update');
    }

    updateFields.push('updated_ts = ?');
    updateValues.push(Math.floor(Date.now() / 1000));

    updateValues.push(id);

    const stmt = db.prepare(`
      UPDATE identity_providers
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `);

    await stmt.bind(...updateValues).run();

    return jsonResponse({
      message: 'Identity provider updated successfully'
    });
  } catch (error) {
    console.error('Error updating identity provider:', error);
    return errorResponse('Failed to update identity provider', 500);
  }
});

// 删除身份提供商 - 需要管理员权限
app.delete('/:id', async (c) => {
  const authError = await requireAdmin(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const id = c.req.param('id');

    const stmt = db.prepare('DELETE FROM identity_providers WHERE id = ?');
    const result = await stmt.bind(id).run();

    if (result.changes === 0) {
      return errorResponse('Identity provider not found', 404);
    }

    return jsonResponse({
      message: 'Identity provider deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting identity provider:', error);
    return errorResponse('Failed to delete identity provider', 500);
  }
});

export default app;
