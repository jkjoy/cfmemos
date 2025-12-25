import { Hono } from 'hono';
import { errorResponse } from '../utils/auth';

const app = new Hono();

/**
 * 转义XML特殊字符
 */
function escapeXml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * 生成RSS Feed
 */
function generateRssFeed(options) {
  const {
    title,
    description,
    link,
    items = []
  } = options;

  const now = new Date().toUTCString();

  let rssItems = '';
  for (const item of items) {
    const pubDate = new Date(item.createdTs * 1000).toUTCString();

    // 构建内容HTML
    let contentHtml = escapeXml(item.content || '');

    // 添加图片资源
    if (item.resourceList && item.resourceList.length > 0) {
      const imageResources = item.resourceList.filter(r => r.type && r.type.startsWith('image/'));
      if (imageResources.length > 0) {
        contentHtml += '\n\n';
        imageResources.forEach(resource => {
          // 构建完整的图片URL
          const imageUrl = resource.filepath.startsWith('http')
            ? resource.filepath
            : `${link}${resource.filepath}`;
          contentHtml += `&lt;img src="${escapeXml(imageUrl)}" alt="${escapeXml(resource.filename)}" style="max-width: 100%; height: auto;" /&gt;\n`;
        });
      }
    }

    rssItems += `
    <item>
      <title>${escapeXml(item.title || `Memo #${item.id}`)}</title>
      <link>${escapeXml(link)}/m/${item.id}</link>
      <guid isPermaLink="true">${escapeXml(link)}/m/${item.id}</guid>
      <pubDate>${pubDate}</pubDate>
      <description><![CDATA[${contentHtml}]]></description>
      ${item.creatorName ? `<author>${escapeXml(item.creatorName)}</author>` : ''}
    </item>`;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(title)}</title>
    <link>${escapeXml(link)}</link>
    <description>${escapeXml(description)}</description>
    <language>zh-CN</language>
    <lastBuildDate>${now}</lastBuildDate>
    <atom:link href="${escapeXml(link)}" rel="self" type="application/rss+xml" />
    ${rssItems}
  </channel>
</rss>`;
}

/**
 * 获取网站基础URL
 */
function getBaseUrl(request) {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

/**
 * 全站RSS - /rss.xml
 */
app.get('/rss.xml', async (c) => {
  try {
    const db = c.env.DB;
    const baseUrl = getBaseUrl(c.req.raw);

    // 获取最近50条公开的memo
    const stmt = db.prepare(`
      SELECT
        m.id,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.content,
        u.nickname as creatorName,
        u.username as creatorUsername
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE m.row_status = 'NORMAL' AND m.visibility = 'PUBLIC'
      ORDER BY m.created_ts DESC
      LIMIT 50
    `);

    const { results: memos } = await stmt.all();

    // 获取每个memo的资源列表
    for (let memo of memos) {
      const resourceStmt = db.prepare(`
        SELECT r.id, r.filename, r.filepath, r.type, r.size
        FROM resources r
        JOIN memo_resources mr ON r.id = mr.resource_id
        WHERE mr.memo_id = ?
      `);
      const { results: resources } = await resourceStmt.bind(memo.id).all();

      // 转换资源路径
      memo.resourceList = (resources || []).map(r => ({
        ...r,
        filepath: r.filepath.startsWith('http') || r.filepath.startsWith('/api/')
          ? r.filepath
          : `/api/v1/resource/${r.id}/file`
      }));
    }

    const rssFeed = generateRssFeed({
      title: 'Memos - 全站动态',
      description: '最新的备忘录更新',
      link: baseUrl,
      items: memos
    });

    return new Response(rssFeed, {
      headers: {
        'Content-Type': 'application/rss+xml; charset=utf-8',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  } catch (error) {
    console.error('Error generating RSS feed:', error);
    return errorResponse('Failed to generate RSS feed', 500);
  }
});

/**
 * 用户RSS - /u/:userId/rss.xml
 */
app.get('/u/:userId/rss.xml', async (c) => {
  try {
    const db = c.env.DB;
    const userId = c.req.param('userId');
    const baseUrl = getBaseUrl(c.req.raw);

    // 验证用户是否存在
    const userStmt = db.prepare('SELECT id, username, nickname FROM users WHERE id = ?');
    const user = await userStmt.bind(userId).first();

    if (!user) {
      return errorResponse('User not found', 404);
    }

    // 获取该用户最近50条公开的memo
    const stmt = db.prepare(`
      SELECT
        m.id,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.content,
        u.nickname as creatorName,
        u.username as creatorUsername
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE m.creator_id = ? AND m.row_status = 'NORMAL' AND m.visibility = 'PUBLIC'
      ORDER BY m.created_ts DESC
      LIMIT 50
    `);

    const { results: memos } = await stmt.bind(userId).all();

    // 获取每个memo的资源列表
    for (let memo of memos) {
      const resourceStmt = db.prepare(`
        SELECT r.id, r.filename, r.filepath, r.type, r.size
        FROM resources r
        JOIN memo_resources mr ON r.id = mr.resource_id
        WHERE mr.memo_id = ?
      `);
      const { results: resources } = await resourceStmt.bind(memo.id).all();

      // 转换资源路径
      memo.resourceList = (resources || []).map(r => ({
        ...r,
        filepath: r.filepath.startsWith('http') || r.filepath.startsWith('/api/')
          ? r.filepath
          : `/api/v1/resource/${r.id}/file`
      }));
    }

    const rssFeed = generateRssFeed({
      title: `Memos - ${user.nickname || user.username} 的动态`,
      description: `${user.nickname || user.username} 的最新备忘录`,
      link: `${baseUrl}/user/${userId}`,
      items: memos
    });

    return new Response(rssFeed, {
      headers: {
        'Content-Type': 'application/rss+xml; charset=utf-8',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  } catch (error) {
    console.error('Error generating user RSS feed:', error);
    return errorResponse('Failed to generate RSS feed', 500);
  }
});

export default app;
