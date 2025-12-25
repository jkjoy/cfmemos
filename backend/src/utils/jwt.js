// JWT 工具函数 - 使用 Web Crypto API 实现
// 兼容 Cloudflare Workers 环境

// Base64URL 编码（JWT 标准格式）
function base64UrlEncode(buffer) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  return base64;
}

// Base64URL 解码
function base64UrlDecode(str) {
  // 添加填充
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }

  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// 字符串转 Uint8Array
function stringToUint8Array(str) {
  return new TextEncoder().encode(str);
}

/**
 * 生成 JWT Token
 * @param {Object} payload - JWT 负载数据（用户信息等）
 * @param {string} secret - 签名密钥
 * @param {number} expiresIn - 过期时间（秒），默认 30 天
 * @returns {Promise<string>} JWT Token
 */
export async function generateJWT(payload, secret, expiresIn = 30 * 24 * 60 * 60) {
  // JWT Header
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  // 添加过期时间到 payload
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = {
    ...payload,
    iat: now,  // issued at
    exp: now + expiresIn  // expiration time
  };

  // 编码 Header 和 Payload
  const encodedHeader = base64UrlEncode(stringToUint8Array(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(stringToUint8Array(JSON.stringify(jwtPayload)));

  // 创建签名输入
  const signatureInput = `${encodedHeader}.${encodedPayload}`;

  // 导入密钥
  const key = await crypto.subtle.importKey(
    'raw',
    stringToUint8Array(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // 生成签名
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    stringToUint8Array(signatureInput)
  );

  // 编码签名
  const encodedSignature = base64UrlEncode(signature);

  // 返回完整的 JWT
  return `${signatureInput}.${encodedSignature}`;
}

/**
 * 验证并解码 JWT Token
 * @param {string} token - JWT Token
 * @param {string} secret - 签名密钥
 * @returns {Promise<Object|null>} 解码后的 payload，验证失败返回 null
 */
export async function verifyJWT(token, secret) {
  try {
    // 分离 JWT 的三部分
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    // 重新生成签名输入
    const signatureInput = `${encodedHeader}.${encodedPayload}`;

    // 导入密钥
    const key = await crypto.subtle.importKey(
      'raw',
      stringToUint8Array(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // 解码原始签名
    const signature = base64UrlDecode(encodedSignature);

    // 验证签名
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      stringToUint8Array(signatureInput)
    );

    if (!isValid) {
      return null;
    }

    // 解码 payload
    const payloadBytes = base64UrlDecode(encodedPayload);
    const payloadStr = new TextDecoder().decode(payloadBytes);
    const payload = JSON.parse(payloadStr);

    // 检查是否过期
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null;  // Token 已过期
    }

    return payload;
  } catch (error) {
    console.error('JWT verification error:', error);
    return null;
  }
}

/**
 * 获取 JWT 密钥（从环境变量或生成随机密钥）
 * @param {Object} env - 环境变量对象
 * @returns {string} JWT 密钥
 */
export function getJWTSecret(env) {
  // 优先使用环境变量中的密钥
  if (env.JWT_SECRET) {
    return env.JWT_SECRET;
  }

  // 如果没有配置，使用一个默认密钥（生产环境应该配置 JWT_SECRET）
  console.warn('Warning: Using default JWT secret. Please set JWT_SECRET environment variable in production.');
  return 'cloudflare-memos-default-jwt-secret-please-change-in-production';
}
