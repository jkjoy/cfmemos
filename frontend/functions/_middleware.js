// Cloudflare Pages Functions 中间件
// 用于代理 API 请求到后端 Worker

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // RSS URL 重写：直接重写到实际的 API 路径，避免重定向
  if (url.pathname === '/rss.xml') {
    url.pathname = '/api/v1/rss/rss.xml';
  } else if (url.pathname.match(/^\/u\/\d+\/rss\.xml$/)) {
    // 从 /u/1/rss.xml 重写为 /api/v1/rss/u/1/rss.xml
    const userId = url.pathname.match(/^\/u\/(\d+)\/rss\.xml$/)[1];
    url.pathname = `/api/v1/rss/u/${userId}/rss.xml`;
  }

  // 需要代理到后端的路径模式
  const shouldProxy =
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/o/');

  if (shouldProxy) {
    // 使用 Service Binding（内部调用，更快更安全）
    if (env.BACKEND) {
      // 使用重写后的 URL 创建新请求
      const proxyRequest = new Request(url.toString(), request);
      const response = await env.BACKEND.fetch(proxyRequest);

      // 如果是重定向且重定向到同域，自动跟随一次
      if (response.status === 301 || response.status === 302) {
        const location = response.headers.get('Location');
        if (location && location.startsWith('/')) {
          // 相对路径重定向，再次请求
          const redirectUrl = new URL(location, request.url);
          const redirectRequest = new Request(redirectUrl.toString(), request);
          return env.BACKEND.fetch(redirectRequest);
        }
      }

      return response;
    }

    // 如果没有配置 Service Binding，回退到默认后端 URL
    // 注意：配置 Service Binding 后，这段代码不会执行
    const backendUrl = 'https://memos-api.zxd.im' + url.pathname + url.search;
    const response = await fetch(backendUrl, {
      method: request.method,
      headers: request.headers,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
    });

    // 如果是重定向且重定向到同域，自动跟随一次
    if (response.status === 301 || response.status === 302) {
      const location = response.headers.get('Location');
      if (location && location.startsWith('/')) {
        const redirectUrl = 'https://memos-api.zxd.im' + location;
        return fetch(redirectUrl, {
          method: request.method,
          headers: request.headers,
          body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        });
      }
    }

    return response;
  }

  // 其他请求继续正常处理（由前端 SPA 处理）
  return context.next();
}
