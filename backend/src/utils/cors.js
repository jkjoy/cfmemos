// CORS 配置
export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
};

// 处理CORS预检请求
export function handleCORS() {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
}