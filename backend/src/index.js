import { Hono } from 'hono';
import { cors } from 'hono/cors';
import authApp from './handlers/auth';
import memosApp from './handlers/memos';
import memoRelationsApp from './handlers/memoRelations';
import tagsApp from './handlers/tags';
import usersApp from './handlers/users';
import userSettingsApp from './handlers/userSettings';
import resourcesApp from './handlers/resources';
import settingsApp from './handlers/settings';
import rssApp from './handlers/rss';
import accessTokensApp from './handlers/accessTokens';
import webhooksApp from './handlers/webhooks';
import identityProvidersApp from './handlers/identityProviders';

const app = new Hono();

app.use('/*', cors({
  origin: (origin) => {
    // 返回实际的origin，这样可以支持任何域名且允许携带凭证
    // 如果没有origin（比如同源请求或某些工具），返回true
    return origin || true;
  },
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Token'],
  exposeHeaders: ['Content-Length', 'Content-Type', 'X-Token'],
  maxAge: 86400,  // 24小时
  credentials: true,  // 支持携带凭证（cookies, authorization headers）
}));

// API 路由
app.route('/api/v1/auth', authApp);       // 认证路由（新增）
app.route('/api/v1/memo', memosApp);
app.route('/api/v1/memo', memoRelationsApp);  // Memo关系路由（评论/引用）
app.route('/api/v1/tag', tagsApp);        // 标签管理路由
app.route('/api/v1/user', usersApp);
app.route('/api/v1/user', accessTokensApp);  // Access Tokens 路由
app.route('/api/v1/user/setting', userSettingsApp);  // 用户设置路由
app.route('/api/v1/resource', resourcesApp);
app.route('/api/v1/settings', settingsApp);
app.route('/api/v1/system/setting', settingsApp);  // 系统设置路由（前端使用这个路径）
app.route('/api/v1/webhook', webhooksApp);  // Webhook 路由
app.route('/api/v1/idp', identityProvidersApp);  // Identity Providers 路由

// Storage 路由 - 返回空列表（暂时未实现）
app.get('/api/v1/storage', async (c) => {
  return c.json([]);
});

// RSS 路由
app.route('/api/v1/rss', rssApp);

// 简单健康检查端点
app.get('/api/v1/ping', (c) => {
  return c.json({ status: 'ok' });
});

// 数据库 VACUUM 端点
app.post('/api/v1/system/vacuum', async (c) => {
  try {
    const db = c.env.DB;

    // 注意：Cloudflare D1 可能不支持 VACUUM 命令
    // 因为它是基于云的 SQLite，优化由平台自动处理
    // 这里尝试执行，如果失败则返回友好消息
    try {
      await db.prepare('VACUUM').run();
      return c.json({
        status: 'ok',
        message: 'Database vacuumed successfully'
      });
    } catch (vacuumError) {
      console.log('VACUUM command not supported on Cloudflare D1:', vacuumError);
      // D1 自动优化数据库，不需要手动 VACUUM
      return c.json({
        status: 'ok',
        message: 'Database optimization is handled automatically by Cloudflare D1'
      });
    }
  } catch (error) {
    console.error('Error in vacuum endpoint:', error);
    return c.json({
      status: 'error',
      message: 'Failed to vacuum database'
    }, 500);
  }
});

// 详细系统状态端点
app.get('/api/v1/status', async (c) => {
  try {
    const db = c.env.DB;

    // 获取系统统计信息
    const userCountStmt = db.prepare('SELECT COUNT(*) as count FROM users');
    const memoCountStmt = db.prepare('SELECT COUNT(*) as count FROM memos WHERE row_status = "NORMAL"');
    const resourceCountStmt = db.prepare('SELECT COUNT(*) as count FROM resources');

    const userCount = await userCountStmt.first();
    const memoCount = await memoCountStmt.first();
    const resourceCount = await resourceCountStmt.first();

    // 获取host用户信息（第一个用户或role='host'的用户）
    const hostStmt = db.prepare(`
      SELECT id, username, nickname, email, role
      FROM users
      WHERE role = 'host' OR is_admin = 1
      ORDER BY id ASC
      LIMIT 1
    `);
    const hostUser = await hostStmt.first();

    // 获取系统设置
    const settingsStmt = db.prepare('SELECT key, value FROM settings');
    const { results: settingsResults } = await settingsStmt.all();

    const settings = {};
    settingsResults.forEach(setting => {
      settings[setting.key] = setting.value;
    });

    // 解析 JSON 字符串格式的设置
    const parseSettingValue = (value) => {
      if (!value) return '';
      try {
        // 如果是 JSON 字符串，则解析它
        return JSON.parse(value);
      } catch (e) {
        // 如果解析失败，直接返回原值
        return value;
      }
    };

    const response = {
      status: 'ok',
      version: 'v1',
      timestamp: Date.now(),
      profile: {
        mode: 'prod',
        version: '1.0.0'
      },
      dbSize: 0,
      allowSignUp: settings.allow_registration === 'true',
      disablePasswordLogin: settings['disable-password-login'] === 'true',
      disablePublicMemos: settings['disable-public-memos'] === 'true',
      maxUploadSizeMiB: parseInt(parseSettingValue(settings['max-upload-size-mib'])) || 50,
      autoBackupInterval: parseInt(parseSettingValue(settings['auto-backup-interval'])) || 0,
      additionalStyle: parseSettingValue(settings['additional-style']) || '',
      additionalScript: parseSettingValue(settings['additional-script']) || '',
      memoDisplayWithUpdatedTs: settings['memo-display-with-updated-ts'] === 'true',
      timezone: c.env.TIMEZONE || '',  // 从环境变量读取时区配置
      customizedProfile: (() => {
        // 从数据库读取 customized-profile 设置
        const customizedProfileStr = settings['customized-profile'];
        if (customizedProfileStr) {
          try {
            const parsed = JSON.parse(customizedProfileStr);
            // 确保所有字段都有值，使用默认值填充缺失的字段
            return {
              name: parsed.name || settings.site_title || 'Memos',
              logoUrl: parsed.logoUrl || '/logo.png',
              description: parsed.description || '',
              locale: parsed.locale || 'zh-Hans',
              appearance: parsed.appearance || 'system',
              externalUrl: parsed.externalUrl || ''
            };
          } catch (e) {
            console.error('Failed to parse customized-profile:', e);
          }
        }
        // 如果没有自定义配置，返回默认值
        return {
          name: settings.site_title || 'Memos',
          logoUrl: '/logo.png',
          description: '',
          locale: 'zh-Hans',
          appearance: 'system',
          externalUrl: ''
        };
      })(),
      stats: {
        users: userCount.count,
        memos: memoCount.count,
        resources: resourceCount.count
      },
      settings: {
        siteTitle: settings.site_title || 'Memos',
        allowRegistration: settings.allow_registration === 'true'
      },
      features: {
        authentication: true,
        memoRelations: true,
        tags: true,
        resources: true,
        rss: true
      }
    };

    // 只有存在host用户时才添加host字段
    if (hostUser) {
      response.host = {
        id: hostUser.id,
        name: `users/${hostUser.username}`,
        username: hostUser.username,
        nickname: hostUser.nickname,
        email: hostUser.email || '',
        role: hostUser.role
      };
    }

    return c.json(response);
  } catch (error) {
    console.error('Error fetching system status:', error);
    return c.json({
      status: 'error',
      message: 'Failed to fetch system status',
      timestamp: Date.now()
    }, 500);
  }
});

// 健康检查端点（向后兼容）
app.get('/api/health', (c) => {
  return c.json({
    status: 'ok',
    timestamp: Date.now(),
    version: 'v1'
  });
});

// 顶层 RSS 路由（需要在通配符路由之前）
// 全站 RSS Feed
app.get('/rss.xml', async (c) => {
  // 重定向到 API RSS 路由
  const apiPath = '/api/v1/rss/rss.xml';
  return c.redirect(apiPath);
});

// 用户 RSS Feed - 通过 ID
app.get('/u/:userId/rss.xml', async (c) => {
  const userId = c.req.param('userId');
  const apiPath = `/api/v1/rss/u/${userId}/rss.xml`;
  return c.redirect(apiPath);
});

// 资源文件访问路由 /o/r/:id/:filename
// 允许通过 /o/r/1/{GUID}.jpg 格式访问资源
app.get('/o/r/:id/:filename', async (c) => {
  try {
    const db = c.env.DB;
    const bucket = c.env.BUCKET;
    const id = c.req.param('id');

    const stmt = db.prepare(`
      SELECT id, filename, filepath, type, size
      FROM resources
      WHERE id = ?
    `);

    const resource = await stmt.bind(id).first();

    if (!resource) {
      return c.text('Resource not found', 404);
    }

    // 从 filepath 中提取 R2 对象的 key（文件名）
    let objectKey = resource.filepath;

    // 如果 filepath 是完整 URL，提取文件名部分
    if (objectKey.startsWith('http')) {
      const url = new URL(objectKey);
      objectKey = url.pathname.substring(1); // 移除开头的 /
    }

    // 从 R2 获取文件
    const object = await bucket.get(objectKey);

    if (!object) {
      return c.text('File not found in storage', 404);
    }

    // 返回文件内容
    return new Response(object.body, {
      headers: {
        'Content-Type': resource.type || 'application/octet-stream',
        'Content-Length': resource.size?.toString() || '',
        'Content-Disposition': `inline; filename="${encodeURIComponent(resource.filename)}"`,
        'Cache-Control': 'public, max-age=31536000',
      },
    });
  } catch (error) {
    console.error('Error proxying resource:', error);
    return c.text('Error accessing resource', 500);
  }
});

// 直接文件访问路由：/:filename (例如: /2_1761140800100.jpeg)
// 这个路由需要放在最后，作为通配符处理文件请求
app.get('/:filename', async (c) => {
  const filename = c.req.param('filename');

  // 检查文件名格式是否匹配：用户ID_时间戳.后缀
  if (filename && filename.match(/^\d+_\d+\.\w+$/)) {
    try {
      const bucket = c.env.BUCKET;

      // 从 R2 获取文件
      const object = await bucket.get(filename);

      if (!object) {
        return c.text('File not found', 404);
      }

      // 获取文件的 MIME 类型
      const contentType = object.httpMetadata?.contentType || 'application/octet-stream';

      // 返回文件内容
      return new Response(object.body, {
        headers: {
          'Content-Type': contentType,
          'Cache-Control': 'public, max-age=31536000',
        },
      });
    } catch (error) {
      console.error('Error serving file:', error);
      return c.text('Error serving file', 500);
    }
  }

  // 如果不匹配文件格式，返回 404
  return c.text('Not Found', 404);
});

// 404 处理
app.notFound((c) => {
  return c.text('Not Found', 404);
});

// 全局错误处理
app.onError((err, c) => {
  console.error('Worker error:', err);
  return c.json({
    error: 'Internal Server Error',
    message: err.message
  }, 500);
});

export default app;