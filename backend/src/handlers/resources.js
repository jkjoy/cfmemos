import { Hono } from 'hono';
import { requireAuth, jsonResponse, errorResponse, ensureDefaultUser } from '../utils/auth';

const app = new Hono();

// 获取资源列表 - 只返回当前用户的资源
app.get('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const currentUser = c.get('user');
    const limit = parseInt(c.req.query('limit')) || 20;
    const offset = parseInt(c.req.query('offset')) || 0;

    // 只返回当前用户创建的资源
    // 使用子查询获取第一个关联的 memo_id（只返回状态为 NORMAL 的 memo）
    // 如果 memo 被删除，memoId 返回 NULL，资源会被归类为"未使用的资源"
    const stmt = db.prepare(`
      SELECT r.id, r.filename, r.filepath, r.type, r.size, r.created_ts,
             u.username as creator_username, u.nickname as creator_name,
             (
               SELECT mr.memo_id
               FROM memo_resources mr
               JOIN memos m ON mr.memo_id = m.id AND m.row_status = 'NORMAL'
               WHERE mr.resource_id = r.id
               LIMIT 1
             ) as memoId
      FROM resources r
      LEFT JOIN users u ON r.creator_id = u.id
      WHERE r.creator_id = ?
      ORDER BY r.created_ts DESC
      LIMIT ? OFFSET ?
    `);

    const { results } = await stmt.bind(currentUser.id, limit, offset).all();

    // 转换时间戳为毫秒并转换字段名为 camelCase
    const formattedResults = results.map(r => ({
      id: r.id,
      filename: r.filename,
      filepath: r.filepath,
      type: r.type,
      size: r.size,
      createdTs: r.created_ts * 1000,  // 转换为毫秒并使用 camelCase
      creatorUsername: r.creator_username,
      creatorName: r.creator_name,
      memoId: r.memoId  // 只有关联到正常memo时才有值，否则为 null
    }));

    return jsonResponse(formattedResults);
  } catch (error) {
    console.error('Error fetching resources:', error);
    return errorResponse('Failed to fetch resources', 500);
  }
});

// 文件代理路由 - 直接从 R2 读取并返回
app.get('/:id/file', async (c) => {
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
      return errorResponse('Resource not found', 404);
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
      return errorResponse('File not found in storage', 404);
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
    return errorResponse('Failed to access resource', 500);
  }
});

// 获取单个资源 - 无需权限
app.get('/:id', async (c) => {
  try {
    const db = c.env.DB;
    const id = c.req.param('id');
    
    const stmt = db.prepare(`
      SELECT id, filename, filepath, type, size, created_ts
      FROM resources
      WHERE id = ?
    `);
    
    const resource = await stmt.bind(id).first();
    
    if (!resource) {
      return errorResponse('Resource not found', 404);
    }
    
    // 如果是图片，直接重定向到存储的URL
    if (resource.filepath.startsWith('http')) {
      return Response.redirect(resource.filepath, 302);
    }
    
    return jsonResponse(resource);
  } catch (error) {
    console.error('Error fetching resource:', error);
    return errorResponse('Failed to fetch resource', 500);
  }
});

// 上传资源 - 需要权限
app.post('/', async (c) => {
  const authError = await requireAuth(c);
  if (authError) return authError;

  try {
    const db = c.env.DB;
    const bucket = c.env.BUCKET;

    const formData = await c.req.formData();
    const file = formData.get('file');

    if (!file) {
      return errorResponse('No file provided');
    }

    // 文件大小验证 (最大 32MB)
    const MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB
    if (file.size > MAX_FILE_SIZE) {
      return errorResponse(`File size exceeds maximum allowed size of ${MAX_FILE_SIZE / 1024 / 1024}MB`);
    }

    // 文件类型白名单验证 - 扩展支持更多类型
    const ALLOWED_TYPES = [
      // 图片
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/svg+xml',
      'image/bmp',
      'image/tiff',
      // 文档
      'application/pdf',
      'text/plain',
      'text/markdown',
      'text/html',
      'text/css',
      'text/javascript',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      // 压缩文件
      'application/zip',
      'application/x-zip-compressed',
      'application/x-rar-compressed',
      'application/x-7z-compressed',
      'application/gzip',
      'application/x-tar',
      // 视频
      'video/mp4',
      'video/mpeg',
      'video/quicktime',
      'video/x-msvideo',
      'video/x-ms-wmv',
      'video/webm',
      // 音频
      'audio/mpeg',
      'audio/wav',
      'audio/ogg',
      'audio/webm',
      'audio/mp4',
      // 其他
      'application/json',
      'text/csv',
      'application/xml',
      'text/xml'
    ];

    if (!ALLOWED_TYPES.includes(file.type)) {
      return errorResponse(`File type '${file.type}' is not allowed. Allowed types: images, videos, audio, PDF, documents, and archives.`);
    }

    // 文件名验证 (防止路径遍历攻击)
    const filename = file.name;
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return errorResponse('Invalid filename');
    }

    // 获取创建者ID（从认证信息获取）
    let creatorId = c.get('user')?.id;

    // 如果没有用户信息，使用默认管理员
    if (!creatorId) {
      creatorId = await ensureDefaultUser(c.env.DB);
    }

    // 生成文件名：用户ID_时间戳.后缀
    const timestamp = Date.now();
    const fileExtension = file.name.split('.').pop();
    const uniqueFilename = `${creatorId}_${timestamp}.${fileExtension}`;

    // 上传到R2存储
    const uploadResult = await bucket.put(uniqueFilename, file.stream(), {
      httpMetadata: {
        contentType: file.type,
      },
    });

    if (!uploadResult) {
      return errorResponse('Failed to upload file', 500);
    }

    // 保存资源信息到数据库 - filepath 存储文件名
    const stmt = db.prepare(`
      INSERT INTO resources (creator_id, filename, filepath, type, size)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = await stmt.bind(
      creatorId,
      file.name,
      uniqueFilename,  // 存储文件名
      file.type,
      file.size
    ).run();

    const resourceId = result.meta.last_row_id;

    // 获取 Worker 的 URL（从请求中获取）
    const workerUrl = new URL(c.req.url).origin;
    const fileUrl = `${workerUrl}/${uniqueFilename}`;

    return jsonResponse({
      id: resourceId,
      filename: file.name,
      filepath: fileUrl,  // 返回完整 URL
      type: file.type,
      size: file.size,
      message: 'File uploaded successfully'
    }, 201);
  } catch (error) {
    console.error('Error uploading resource:', error);
    return errorResponse('Failed to upload resource', 500);
  }
});

export default app;
