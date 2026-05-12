var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/utils/jwt.js
var jwt_exports = {};
__export(jwt_exports, {
  generateJWT: () => generateJWT,
  getJWTSecret: () => getJWTSecret,
  verifyJWT: () => verifyJWT
});
function base64UrlEncode(buffer) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return base64;
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) {
    str += "=";
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
function stringToUint8Array(str) {
  return new TextEncoder().encode(str);
}
async function generateJWT(payload, secret, expiresIn = 30 * 24 * 60 * 60) {
  const header = {
    alg: "HS256",
    typ: "JWT"
  };
  const now = Math.floor(Date.now() / 1e3);
  const jwtPayload = {
    ...payload,
    iat: now,
    // issued at
    exp: now + expiresIn
    // expiration time
  };
  const encodedHeader = base64UrlEncode(stringToUint8Array(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(stringToUint8Array(JSON.stringify(jwtPayload)));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    stringToUint8Array(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    stringToUint8Array(signatureInput)
  );
  const encodedSignature = base64UrlEncode(signature);
  return `${signatureInput}.${encodedSignature}`;
}
async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const key = await crypto.subtle.importKey(
      "raw",
      stringToUint8Array(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signature = base64UrlDecode(encodedSignature);
    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      stringToUint8Array(signatureInput)
    );
    if (!isValid) {
      return null;
    }
    const payloadBytes = base64UrlDecode(encodedPayload);
    const payloadStr = new TextDecoder().decode(payloadBytes);
    const payload = JSON.parse(payloadStr);
    const now = Math.floor(Date.now() / 1e3);
    if (payload.exp && payload.exp < now) {
      return null;
    }
    return payload;
  } catch (error) {
    console.error("JWT verification error:", error);
    return null;
  }
}
function getJWTSecret(env) {
  if (env.JWT_SECRET) {
    return env.JWT_SECRET;
  }
  if (!hasWarnedForDefaultJWTSecret) {
    console.warn("Warning: Using default JWT secret. Set JWT_SECRET in .dev.vars for local development and via `wrangler secret put JWT_SECRET` for deployment.");
    hasWarnedForDefaultJWTSecret = true;
  }
  return "cloudflare-memos-default-jwt-secret-please-change-in-production";
}
var hasWarnedForDefaultJWTSecret;
var init_jwt = __esm({
  "src/utils/jwt.js"() {
    hasWarnedForDefaultJWTSecret = false;
    __name(base64UrlEncode, "base64UrlEncode");
    __name(base64UrlDecode, "base64UrlDecode");
    __name(stringToUint8Array, "stringToUint8Array");
    __name(generateJWT, "generateJWT");
    __name(verifyJWT, "verifyJWT");
    __name(getJWTSecret, "getJWTSecret");
  }
});

// src/utils/auth.js
var auth_exports = {};
__export(auth_exports, {
  canModifyRole: () => canModifyRole,
  cleanupExpiredSessions: () => cleanupExpiredSessions,
  createSession: () => createSession,
  deleteSession: () => deleteSession,
  ensureDefaultUser: () => ensureDefaultUser,
  errorResponse: () => errorResponse,
  generateSecurePassword: () => generateSecurePassword,
  generateSessionToken: () => generateSessionToken,
  getRequestBody: () => getRequestBody,
  hashPassword: () => hashPassword,
  isValidRole: () => isValidRole,
  jsonResponse: () => jsonResponse,
  needsPasswordUpgrade: () => needsPasswordUpgrade,
  requireAdmin: () => requireAdmin,
  requireAuth: () => requireAuth,
  requireHost: () => requireHost,
  upgradePasswordHash: () => upgradePasswordHash,
  validateSession: () => validateSession,
  verifyPassword: () => verifyPassword
});
async function hashPassword(password, salt = null) {
  const encoder = new TextEncoder();
  if (!salt) {
    salt = crypto.getRandomValues(new Uint8Array(16));
  } else if (typeof salt === "string") {
    salt = new Uint8Array(salt.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
  }
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 1e5,
      // 10万次迭代
      hash: "SHA-256"
    },
    keyMaterial,
    256
    // 256位输出
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const saltArray = Array.from(new Uint8Array(salt));
  const saltHex = saltArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${saltHex}$${hashHex}`;
}
async function verifyPassword(password, hashedPassword) {
  try {
    if (hashedPassword.includes("$")) {
      const [saltHex, hashHex] = hashedPassword.split("$");
      if (!saltHex || !hashHex) {
        return false;
      }
      const newHash = await hashPassword(password, saltHex);
      return newHash === hashedPassword;
    } else {
      const encoder = new TextEncoder();
      const data = encoder.encode(password);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const oldHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
      return oldHash === hashedPassword;
    }
  } catch (error) {
    console.error("Error verifying password:", error);
    return false;
  }
}
function needsPasswordUpgrade(hashedPassword) {
  return !hashedPassword.includes("$");
}
async function upgradePasswordHash(db, userId, newHash) {
  try {
    const stmt = db.prepare(`
      UPDATE users
      SET password_hash = ?, updated_ts = ?
      WHERE id = ?
    `);
    const now = Math.floor(Date.now() / 1e3);
    await stmt.bind(newHash, now, userId).run();
    return true;
  } catch (error) {
    console.error("Error upgrading password hash:", error);
    return false;
  }
}
function generateSessionToken() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  const tokenArray = Array.from(randomBytes);
  return tokenArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function createSession(db, userId, ipAddress = null, userAgent = null) {
  try {
    const token = generateSessionToken();
    const now = Math.floor(Date.now() / 1e3);
    const expiresTs = now + 30 * 24 * 60 * 60;
    const stmt = db.prepare(`
      INSERT INTO sessions (user_id, token, created_ts, expires_ts, last_active_ts, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    await stmt.bind(userId, token, now, expiresTs, now, ipAddress, userAgent).run();
    return token;
  } catch (error) {
    console.error("Error creating session:", error);
    return null;
  }
}
async function validateSession(db, token) {
  try {
    const now = Math.floor(Date.now() / 1e3);
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
      role: session.role || (session.is_admin ? "admin" : "user")
    };
  } catch (error) {
    console.error("Error validating session:", error);
    return null;
  }
}
async function deleteSession(db, token) {
  try {
    const stmt = db.prepare("DELETE FROM sessions WHERE token = ?");
    await stmt.bind(token).run();
    return true;
  } catch (error) {
    console.error("Error deleting session:", error);
    return false;
  }
}
async function cleanupExpiredSessions(db) {
  try {
    const now = Math.floor(Date.now() / 1e3);
    const stmt = db.prepare("DELETE FROM sessions WHERE expires_ts < ?");
    await stmt.bind(now).run();
  } catch (error) {
    console.error("Error cleaning up expired sessions:", error);
  }
}
function generateSecurePassword(length = 16) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  const randomBytes = crypto.getRandomValues(new Uint8Array(length));
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[randomBytes[i] % charset.length];
  }
  return password;
}
async function ensureDefaultUser(db) {
  try {
    const userCheck = await db.prepare("SELECT COUNT(*) as count FROM users").first();
    if (userCheck.count === 0) {
      const randomPassword = generateSecurePassword(16);
      const passwordHash = await hashPassword(randomPassword);
      const userStmt = db.prepare(`
        INSERT INTO users (username, nickname, password_hash, is_admin)
        VALUES (?, ?, ?, 1)
      `);
      const userResult = await userStmt.bind("admin", "\u7BA1\u7406\u5458", passwordHash).run();
      console.log("=".repeat(60));
      console.log("\u26A0\uFE0F  IMPORTANT: Default admin user created");
      console.log("Username: admin");
      console.log(`Password: ${randomPassword}`);
      console.log("Please change this password immediately after first login!");
      console.log("=".repeat(60));
      return userResult.meta.last_row_id;
    } else {
      const firstUser = await db.prepare("SELECT id FROM users ORDER BY id ASC LIMIT 1").first();
      return firstUser?.id || 1;
    }
  } catch (error) {
    console.error("Error ensuring default user:", error);
    return 1;
  }
}
async function requireAuth(c) {
  const isHonoContext = typeof c.req !== "undefined";
  let authHeader, token, db, env;
  if (isHonoContext) {
    authHeader = c.req.header("Authorization");
    token = authHeader?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    db = c.env.DB;
    env = c.env;
  } else {
    authHeader = c.headers.get("Authorization");
    token = authHeader?.replace("Bearer ", "") || c.headers.get("X-Token") || new URL(c.url).searchParams.get("token");
    db = c.env.DB;
    env = c.env;
  }
  if (!token) {
    return jsonResponse({
      error: "Unauthorized",
      message: "Valid token required"
    }, 401);
  }
  if (token.startsWith("eyJ")) {
    try {
      const { verifyJWT: verifyJWT2, getJWTSecret: getJWTSecret2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
      const jwtSecret = getJWTSecret2(env);
      const payload = await verifyJWT2(token, jwtSecret);
      if (payload && db) {
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
              email: dbUser.email || "",
              avatarUrl: dbUser.avatar_url || "",
              isAdmin: Boolean(dbUser.is_admin) || ["host", "admin"].includes(dbUser.role),
              is_admin: Boolean(dbUser.is_admin) || ["host", "admin"].includes(dbUser.role),
              role: dbUser.role || (dbUser.is_admin ? "admin" : "user")
            };
            if (isHonoContext) {
              c.set("user", user);
            } else {
              c.user = user;
            }
            return null;
          }
        } catch (dbError) {
          console.error("Error fetching user from database:", dbError);
          const user = {
            id: payload.id,
            username: payload.username,
            nickname: payload.nickname,
            email: payload.email,
            avatarUrl: "",
            isAdmin: payload.role === 1 || payload.role === 2,
            is_admin: payload.role === 1 || payload.role === 2,
            role: payload.role === 1 ? "host" : payload.role === 2 ? "admin" : "user"
          };
          if (isHonoContext) {
            c.set("user", user);
          } else {
            c.user = user;
          }
          return null;
        }
      }
    } catch (error) {
      console.error("Error validating JWT:", error);
    }
  }
  if (token && /^[0-9a-f]{64}$/.test(token)) {
    if (db) {
      try {
        const user = await validateSession(db, token);
        if (user) {
          if (isHonoContext) {
            c.set("user", user);
          } else {
            c.user = user;
          }
          return null;
        }
      } catch (error) {
        console.error("Error validating user session:", error);
      }
      try {
        const apiTokenStmt = db.prepare(`
          SELECT at.*, u.id as user_id, u.username, u.nickname, u.email, u.is_admin, u.role
          FROM api_tokens at
          JOIN users u ON at.user_id = u.id
          WHERE at.token = ? AND at.is_active = 1
        `);
        const apiTokenResult = await apiTokenStmt.bind(token).first();
        if (apiTokenResult) {
          if (apiTokenResult.expires_ts && apiTokenResult.expires_ts < Math.floor(Date.now() / 1e3)) {
            return jsonResponse({
              error: "Unauthorized",
              message: "Access token has expired"
            }, 401);
          }
          const user = {
            id: apiTokenResult.user_id,
            username: apiTokenResult.username,
            nickname: apiTokenResult.nickname,
            email: apiTokenResult.email,
            isAdmin: Boolean(apiTokenResult.is_admin),
            role: apiTokenResult.role || (apiTokenResult.is_admin ? "admin" : "user")
          };
          if (isHonoContext) {
            c.set("user", user);
          } else {
            c.user = user;
          }
          return null;
        }
      } catch (error) {
        console.error("Error validating access token:", error);
      }
    }
  }
  const expectedToken = env.TOKEN;
  if (expectedToken) {
    if (token === expectedToken) {
      return null;
    }
  }
  return jsonResponse({
    error: "Unauthorized",
    message: "Valid token required"
  }, 401);
}
function jsonResponse(data, status = 200) {
  let jsonString;
  try {
    jsonString = JSON.stringify(data, (key, value) => {
      if (typeof value === "string") {
        return value;
      }
      return value;
    }, 0);
  } catch (error) {
    console.error("JSON serialization error:", error);
    jsonString = JSON.stringify({ error: "Serialization failed" });
  }
  return new Response(jsonString, {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-cache",
      "Accept-Charset": "utf-8",
      ...corsHeaders
    }
  });
}
function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}
async function requireAdmin(c) {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  const user = c.get("user");
  if (!["admin", "host"].includes(user.role) && !user.is_admin) {
    return errorResponse("Admin permission required", 403);
  }
  return null;
}
async function requireHost(c) {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  const user = c.get("user");
  if (user.role !== "host") {
    return errorResponse("Host permission required", 403);
  }
  return null;
}
function isValidRole(role) {
  return ["host", "admin", "user"].includes(role);
}
function canModifyRole(currentUserRole, targetRole) {
  const rolePriority = {
    "host": 3,
    "admin": 2,
    "user": 1
  };
  const currentPriority = rolePriority[currentUserRole] || 0;
  const targetPriority = rolePriority[targetRole] || 0;
  return currentUserRole === "host" || currentUserRole === "admin" && targetPriority < 2;
}
async function getRequestBody(request) {
  try {
    const contentType = request.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      return await request.json();
    }
    return {};
  } catch (error) {
    throw new Error("Invalid JSON in request body");
  }
}
var corsHeaders;
var init_auth = __esm({
  "src/utils/auth.js"() {
    corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With"
    };
    __name(hashPassword, "hashPassword");
    __name(verifyPassword, "verifyPassword");
    __name(needsPasswordUpgrade, "needsPasswordUpgrade");
    __name(upgradePasswordHash, "upgradePasswordHash");
    __name(generateSessionToken, "generateSessionToken");
    __name(createSession, "createSession");
    __name(validateSession, "validateSession");
    __name(deleteSession, "deleteSession");
    __name(cleanupExpiredSessions, "cleanupExpiredSessions");
    __name(generateSecurePassword, "generateSecurePassword");
    __name(ensureDefaultUser, "ensureDefaultUser");
    __name(requireAuth, "requireAuth");
    __name(jsonResponse, "jsonResponse");
    __name(errorResponse, "errorResponse");
    __name(requireAdmin, "requireAdmin");
    __name(requireHost, "requireHost");
    __name(isValidRole, "isValidRole");
    __name(canModifyRole, "canModifyRole");
    __name(getRequestBody, "getRequestBody");
  }
});

// node_modules/hono/dist/compose.js
var compose = /* @__PURE__ */ __name((middleware, onError, onNotFound) => {
  return (context, next) => {
    let index = -1;
    return dispatch(0);
    async function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      index = i;
      let res;
      let isError = false;
      let handler;
      if (middleware[i]) {
        handler = middleware[i][0][0];
        context.req.routeIndex = i;
      } else {
        handler = i === middleware.length && next || void 0;
      }
      if (handler) {
        try {
          res = await handler(context, () => dispatch(i + 1));
        } catch (err) {
          if (err instanceof Error && onError) {
            context.error = err;
            res = await onError(err, context);
            isError = true;
          } else {
            throw err;
          }
        }
      } else {
        if (context.finalized === false && onNotFound) {
          res = await onNotFound(context);
        }
      }
      if (res && (context.finalized === false || isError)) {
        context.res = res;
      }
      return context;
    }
    __name(dispatch, "dispatch");
  };
}, "compose");

// node_modules/hono/dist/request/constants.js
var GET_MATCH_RESULT = Symbol();

// node_modules/hono/dist/utils/body.js
var parseBody = /* @__PURE__ */ __name(async (request, options = /* @__PURE__ */ Object.create(null)) => {
  const { all = false, dot = false } = options;
  const headers = request instanceof HonoRequest ? request.raw.headers : request.headers;
  const contentType = headers.get("Content-Type");
  if (contentType?.startsWith("multipart/form-data") || contentType?.startsWith("application/x-www-form-urlencoded")) {
    return parseFormData(request, { all, dot });
  }
  return {};
}, "parseBody");
async function parseFormData(request, options) {
  const formData = await request.formData();
  if (formData) {
    return convertFormDataToBodyData(formData, options);
  }
  return {};
}
__name(parseFormData, "parseFormData");
function convertFormDataToBodyData(formData, options) {
  const form = /* @__PURE__ */ Object.create(null);
  formData.forEach((value, key) => {
    const shouldParseAllValues = options.all || key.endsWith("[]");
    if (!shouldParseAllValues) {
      form[key] = value;
    } else {
      handleParsingAllValues(form, key, value);
    }
  });
  if (options.dot) {
    Object.entries(form).forEach(([key, value]) => {
      const shouldParseDotValues = key.includes(".");
      if (shouldParseDotValues) {
        handleParsingNestedValues(form, key, value);
        delete form[key];
      }
    });
  }
  return form;
}
__name(convertFormDataToBodyData, "convertFormDataToBodyData");
var handleParsingAllValues = /* @__PURE__ */ __name((form, key, value) => {
  if (form[key] !== void 0) {
    if (Array.isArray(form[key])) {
      ;
      form[key].push(value);
    } else {
      form[key] = [form[key], value];
    }
  } else {
    if (!key.endsWith("[]")) {
      form[key] = value;
    } else {
      form[key] = [value];
    }
  }
}, "handleParsingAllValues");
var handleParsingNestedValues = /* @__PURE__ */ __name((form, key, value) => {
  let nestedForm = form;
  const keys = key.split(".");
  keys.forEach((key2, index) => {
    if (index === keys.length - 1) {
      nestedForm[key2] = value;
    } else {
      if (!nestedForm[key2] || typeof nestedForm[key2] !== "object" || Array.isArray(nestedForm[key2]) || nestedForm[key2] instanceof File) {
        nestedForm[key2] = /* @__PURE__ */ Object.create(null);
      }
      nestedForm = nestedForm[key2];
    }
  });
}, "handleParsingNestedValues");

// node_modules/hono/dist/utils/url.js
var splitPath = /* @__PURE__ */ __name((path) => {
  const paths = path.split("/");
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
}, "splitPath");
var splitRoutingPath = /* @__PURE__ */ __name((routePath) => {
  const { groups, path } = extractGroupsFromPath(routePath);
  const paths = splitPath(path);
  return replaceGroupMarks(paths, groups);
}, "splitRoutingPath");
var extractGroupsFromPath = /* @__PURE__ */ __name((path) => {
  const groups = [];
  path = path.replace(/\{[^}]+\}/g, (match2, index) => {
    const mark = `@${index}`;
    groups.push([mark, match2]);
    return mark;
  });
  return { groups, path };
}, "extractGroupsFromPath");
var replaceGroupMarks = /* @__PURE__ */ __name((paths, groups) => {
  for (let i = groups.length - 1; i >= 0; i--) {
    const [mark] = groups[i];
    for (let j = paths.length - 1; j >= 0; j--) {
      if (paths[j].includes(mark)) {
        paths[j] = paths[j].replace(mark, groups[i][1]);
        break;
      }
    }
  }
  return paths;
}, "replaceGroupMarks");
var patternCache = {};
var getPattern = /* @__PURE__ */ __name((label, next) => {
  if (label === "*") {
    return "*";
  }
  const match2 = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match2) {
    const cacheKey = `${label}#${next}`;
    if (!patternCache[cacheKey]) {
      if (match2[2]) {
        patternCache[cacheKey] = next && next[0] !== ":" && next[0] !== "*" ? [cacheKey, match2[1], new RegExp(`^${match2[2]}(?=/${next})`)] : [label, match2[1], new RegExp(`^${match2[2]}$`)];
      } else {
        patternCache[cacheKey] = [label, match2[1], true];
      }
    }
    return patternCache[cacheKey];
  }
  return null;
}, "getPattern");
var tryDecode = /* @__PURE__ */ __name((str, decoder) => {
  try {
    return decoder(str);
  } catch {
    return str.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match2) => {
      try {
        return decoder(match2);
      } catch {
        return match2;
      }
    });
  }
}, "tryDecode");
var tryDecodeURI = /* @__PURE__ */ __name((str) => tryDecode(str, decodeURI), "tryDecodeURI");
var getPath = /* @__PURE__ */ __name((request) => {
  const url = request.url;
  const start = url.indexOf("/", url.indexOf(":") + 4);
  let i = start;
  for (; i < url.length; i++) {
    const charCode = url.charCodeAt(i);
    if (charCode === 37) {
      const queryIndex = url.indexOf("?", i);
      const path = url.slice(start, queryIndex === -1 ? void 0 : queryIndex);
      return tryDecodeURI(path.includes("%25") ? path.replace(/%25/g, "%2525") : path);
    } else if (charCode === 63) {
      break;
    }
  }
  return url.slice(start, i);
}, "getPath");
var getPathNoStrict = /* @__PURE__ */ __name((request) => {
  const result = getPath(request);
  return result.length > 1 && result.at(-1) === "/" ? result.slice(0, -1) : result;
}, "getPathNoStrict");
var mergePath = /* @__PURE__ */ __name((base, sub, ...rest) => {
  if (rest.length) {
    sub = mergePath(sub, ...rest);
  }
  return `${base?.[0] === "/" ? "" : "/"}${base}${sub === "/" ? "" : `${base?.at(-1) === "/" ? "" : "/"}${sub?.[0] === "/" ? sub.slice(1) : sub}`}`;
}, "mergePath");
var checkOptionalParameter = /* @__PURE__ */ __name((path) => {
  if (path.charCodeAt(path.length - 1) !== 63 || !path.includes(":")) {
    return null;
  }
  const segments = path.split("/");
  const results = [];
  let basePath = "";
  segments.forEach((segment) => {
    if (segment !== "" && !/\:/.test(segment)) {
      basePath += "/" + segment;
    } else if (/\:/.test(segment)) {
      if (/\?/.test(segment)) {
        if (results.length === 0 && basePath === "") {
          results.push("/");
        } else {
          results.push(basePath);
        }
        const optionalSegment = segment.replace("?", "");
        basePath += "/" + optionalSegment;
        results.push(basePath);
      } else {
        basePath += "/" + segment;
      }
    }
  });
  return results.filter((v, i, a) => a.indexOf(v) === i);
}, "checkOptionalParameter");
var _decodeURI = /* @__PURE__ */ __name((value) => {
  if (!/[%+]/.test(value)) {
    return value;
  }
  if (value.indexOf("+") !== -1) {
    value = value.replace(/\+/g, " ");
  }
  return value.indexOf("%") !== -1 ? tryDecode(value, decodeURIComponent_) : value;
}, "_decodeURI");
var _getQueryParam = /* @__PURE__ */ __name((url, key, multiple) => {
  let encoded;
  if (!multiple && key && !/[%+]/.test(key)) {
    let keyIndex2 = url.indexOf(`?${key}`, 8);
    if (keyIndex2 === -1) {
      keyIndex2 = url.indexOf(`&${key}`, 8);
    }
    while (keyIndex2 !== -1) {
      const trailingKeyCode = url.charCodeAt(keyIndex2 + key.length + 1);
      if (trailingKeyCode === 61) {
        const valueIndex = keyIndex2 + key.length + 2;
        const endIndex = url.indexOf("&", valueIndex);
        return _decodeURI(url.slice(valueIndex, endIndex === -1 ? void 0 : endIndex));
      } else if (trailingKeyCode == 38 || isNaN(trailingKeyCode)) {
        return "";
      }
      keyIndex2 = url.indexOf(`&${key}`, keyIndex2 + 1);
    }
    encoded = /[%+]/.test(url);
    if (!encoded) {
      return void 0;
    }
  }
  const results = {};
  encoded ??= /[%+]/.test(url);
  let keyIndex = url.indexOf("?", 8);
  while (keyIndex !== -1) {
    const nextKeyIndex = url.indexOf("&", keyIndex + 1);
    let valueIndex = url.indexOf("=", keyIndex);
    if (valueIndex > nextKeyIndex && nextKeyIndex !== -1) {
      valueIndex = -1;
    }
    let name = url.slice(
      keyIndex + 1,
      valueIndex === -1 ? nextKeyIndex === -1 ? void 0 : nextKeyIndex : valueIndex
    );
    if (encoded) {
      name = _decodeURI(name);
    }
    keyIndex = nextKeyIndex;
    if (name === "") {
      continue;
    }
    let value;
    if (valueIndex === -1) {
      value = "";
    } else {
      value = url.slice(valueIndex + 1, nextKeyIndex === -1 ? void 0 : nextKeyIndex);
      if (encoded) {
        value = _decodeURI(value);
      }
    }
    if (multiple) {
      if (!(results[name] && Array.isArray(results[name]))) {
        results[name] = [];
      }
      ;
      results[name].push(value);
    } else {
      results[name] ??= value;
    }
  }
  return key ? results[key] : results;
}, "_getQueryParam");
var getQueryParam = _getQueryParam;
var getQueryParams = /* @__PURE__ */ __name((url, key) => {
  return _getQueryParam(url, key, true);
}, "getQueryParams");
var decodeURIComponent_ = decodeURIComponent;

// node_modules/hono/dist/request.js
var tryDecodeURIComponent = /* @__PURE__ */ __name((str) => tryDecode(str, decodeURIComponent_), "tryDecodeURIComponent");
var HonoRequest = /* @__PURE__ */ __name(class {
  raw;
  #validatedData;
  #matchResult;
  routeIndex = 0;
  path;
  bodyCache = {};
  constructor(request, path = "/", matchResult = [[]]) {
    this.raw = request;
    this.path = path;
    this.#matchResult = matchResult;
    this.#validatedData = {};
  }
  param(key) {
    return key ? this.#getDecodedParam(key) : this.#getAllDecodedParams();
  }
  #getDecodedParam(key) {
    const paramKey = this.#matchResult[0][this.routeIndex][1][key];
    const param = this.#getParamValue(paramKey);
    return param && /\%/.test(param) ? tryDecodeURIComponent(param) : param;
  }
  #getAllDecodedParams() {
    const decoded = {};
    const keys = Object.keys(this.#matchResult[0][this.routeIndex][1]);
    for (const key of keys) {
      const value = this.#getParamValue(this.#matchResult[0][this.routeIndex][1][key]);
      if (value !== void 0) {
        decoded[key] = /\%/.test(value) ? tryDecodeURIComponent(value) : value;
      }
    }
    return decoded;
  }
  #getParamValue(paramKey) {
    return this.#matchResult[1] ? this.#matchResult[1][paramKey] : paramKey;
  }
  query(key) {
    return getQueryParam(this.url, key);
  }
  queries(key) {
    return getQueryParams(this.url, key);
  }
  header(name) {
    if (name) {
      return this.raw.headers.get(name) ?? void 0;
    }
    const headerData = {};
    this.raw.headers.forEach((value, key) => {
      headerData[key] = value;
    });
    return headerData;
  }
  async parseBody(options) {
    return this.bodyCache.parsedBody ??= await parseBody(this, options);
  }
  #cachedBody = (key) => {
    const { bodyCache, raw: raw2 } = this;
    const cachedBody = bodyCache[key];
    if (cachedBody) {
      return cachedBody;
    }
    const anyCachedKey = Object.keys(bodyCache)[0];
    if (anyCachedKey) {
      return bodyCache[anyCachedKey].then((body) => {
        if (anyCachedKey === "json") {
          body = JSON.stringify(body);
        }
        return new Response(body)[key]();
      });
    }
    return bodyCache[key] = raw2[key]();
  };
  json() {
    return this.#cachedBody("text").then((text) => JSON.parse(text));
  }
  text() {
    return this.#cachedBody("text");
  }
  arrayBuffer() {
    return this.#cachedBody("arrayBuffer");
  }
  blob() {
    return this.#cachedBody("blob");
  }
  formData() {
    return this.#cachedBody("formData");
  }
  addValidatedData(target, data) {
    this.#validatedData[target] = data;
  }
  valid(target) {
    return this.#validatedData[target];
  }
  get url() {
    return this.raw.url;
  }
  get method() {
    return this.raw.method;
  }
  get [GET_MATCH_RESULT]() {
    return this.#matchResult;
  }
  get matchedRoutes() {
    return this.#matchResult[0].map(([[, route]]) => route);
  }
  get routePath() {
    return this.#matchResult[0].map(([[, route]]) => route)[this.routeIndex].path;
  }
}, "HonoRequest");

// node_modules/hono/dist/utils/html.js
var HtmlEscapedCallbackPhase = {
  Stringify: 1,
  BeforeStream: 2,
  Stream: 3
};
var raw = /* @__PURE__ */ __name((value, callbacks) => {
  const escapedString = new String(value);
  escapedString.isEscaped = true;
  escapedString.callbacks = callbacks;
  return escapedString;
}, "raw");
var resolveCallback = /* @__PURE__ */ __name(async (str, phase, preserveCallbacks, context, buffer) => {
  if (typeof str === "object" && !(str instanceof String)) {
    if (!(str instanceof Promise)) {
      str = str.toString();
    }
    if (str instanceof Promise) {
      str = await str;
    }
  }
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return Promise.resolve(str);
  }
  if (buffer) {
    buffer[0] += str;
  } else {
    buffer = [str];
  }
  const resStr = Promise.all(callbacks.map((c) => c({ phase, buffer, context }))).then(
    (res) => Promise.all(
      res.filter(Boolean).map((str2) => resolveCallback(str2, phase, false, context, buffer))
    ).then(() => buffer[0])
  );
  if (preserveCallbacks) {
    return raw(await resStr, callbacks);
  } else {
    return resStr;
  }
}, "resolveCallback");

// node_modules/hono/dist/context.js
var TEXT_PLAIN = "text/plain; charset=UTF-8";
var setDefaultContentType = /* @__PURE__ */ __name((contentType, headers) => {
  return {
    "Content-Type": contentType,
    ...headers
  };
}, "setDefaultContentType");
var Context = /* @__PURE__ */ __name(class {
  #rawRequest;
  #req;
  env = {};
  #var;
  finalized = false;
  error;
  #status;
  #executionCtx;
  #res;
  #layout;
  #renderer;
  #notFoundHandler;
  #preparedHeaders;
  #matchResult;
  #path;
  constructor(req, options) {
    this.#rawRequest = req;
    if (options) {
      this.#executionCtx = options.executionCtx;
      this.env = options.env;
      this.#notFoundHandler = options.notFoundHandler;
      this.#path = options.path;
      this.#matchResult = options.matchResult;
    }
  }
  get req() {
    this.#req ??= new HonoRequest(this.#rawRequest, this.#path, this.#matchResult);
    return this.#req;
  }
  get event() {
    if (this.#executionCtx && "respondWith" in this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    return this.#res ||= new Response(null, {
      headers: this.#preparedHeaders ??= new Headers()
    });
  }
  set res(_res) {
    if (this.#res && _res) {
      _res = new Response(_res.body, _res);
      for (const [k, v] of this.#res.headers.entries()) {
        if (k === "content-type") {
          continue;
        }
        if (k === "set-cookie") {
          const cookies = this.#res.headers.getSetCookie();
          _res.headers.delete("set-cookie");
          for (const cookie of cookies) {
            _res.headers.append("set-cookie", cookie);
          }
        } else {
          _res.headers.set(k, v);
        }
      }
    }
    this.#res = _res;
    this.finalized = true;
  }
  render = (...args) => {
    this.#renderer ??= (content) => this.html(content);
    return this.#renderer(...args);
  };
  setLayout = (layout) => this.#layout = layout;
  getLayout = () => this.#layout;
  setRenderer = (renderer) => {
    this.#renderer = renderer;
  };
  header = (name, value, options) => {
    if (this.finalized) {
      this.#res = new Response(this.#res.body, this.#res);
    }
    const headers = this.#res ? this.#res.headers : this.#preparedHeaders ??= new Headers();
    if (value === void 0) {
      headers.delete(name);
    } else if (options?.append) {
      headers.append(name, value);
    } else {
      headers.set(name, value);
    }
  };
  status = (status) => {
    this.#status = status;
  };
  set = (key, value) => {
    this.#var ??= /* @__PURE__ */ new Map();
    this.#var.set(key, value);
  };
  get = (key) => {
    return this.#var ? this.#var.get(key) : void 0;
  };
  get var() {
    if (!this.#var) {
      return {};
    }
    return Object.fromEntries(this.#var);
  }
  #newResponse(data, arg, headers) {
    const responseHeaders = this.#res ? new Headers(this.#res.headers) : this.#preparedHeaders ?? new Headers();
    if (typeof arg === "object" && "headers" in arg) {
      const argHeaders = arg.headers instanceof Headers ? arg.headers : new Headers(arg.headers);
      for (const [key, value] of argHeaders) {
        if (key.toLowerCase() === "set-cookie") {
          responseHeaders.append(key, value);
        } else {
          responseHeaders.set(key, value);
        }
      }
    }
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        if (typeof v === "string") {
          responseHeaders.set(k, v);
        } else {
          responseHeaders.delete(k);
          for (const v2 of v) {
            responseHeaders.append(k, v2);
          }
        }
      }
    }
    const status = typeof arg === "number" ? arg : arg?.status ?? this.#status;
    return new Response(data, { status, headers: responseHeaders });
  }
  newResponse = (...args) => this.#newResponse(...args);
  body = (data, arg, headers) => this.#newResponse(data, arg, headers);
  text = (text, arg, headers) => {
    return !this.#preparedHeaders && !this.#status && !arg && !headers && !this.finalized ? new Response(text) : this.#newResponse(
      text,
      arg,
      setDefaultContentType(TEXT_PLAIN, headers)
    );
  };
  json = (object, arg, headers) => {
    return this.#newResponse(
      JSON.stringify(object),
      arg,
      setDefaultContentType("application/json", headers)
    );
  };
  html = (html, arg, headers) => {
    const res = /* @__PURE__ */ __name((html2) => this.#newResponse(html2, arg, setDefaultContentType("text/html; charset=UTF-8", headers)), "res");
    return typeof html === "object" ? resolveCallback(html, HtmlEscapedCallbackPhase.Stringify, false, {}).then(res) : res(html);
  };
  redirect = (location, status) => {
    const locationString = String(location);
    this.header(
      "Location",
      !/[^\x00-\xFF]/.test(locationString) ? locationString : encodeURI(locationString)
    );
    return this.newResponse(null, status ?? 302);
  };
  notFound = () => {
    this.#notFoundHandler ??= () => new Response();
    return this.#notFoundHandler(this);
  };
}, "Context");

// node_modules/hono/dist/router.js
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "options", "patch"];
var MESSAGE_MATCHER_IS_ALREADY_BUILT = "Can not add a route since the matcher is already built.";
var UnsupportedPathError = /* @__PURE__ */ __name(class extends Error {
}, "UnsupportedPathError");

// node_modules/hono/dist/utils/constants.js
var COMPOSED_HANDLER = "__COMPOSED_HANDLER";

// node_modules/hono/dist/hono-base.js
var notFoundHandler = /* @__PURE__ */ __name((c) => {
  return c.text("404 Not Found", 404);
}, "notFoundHandler");
var errorHandler = /* @__PURE__ */ __name((err, c) => {
  if ("getResponse" in err) {
    const res = err.getResponse();
    return c.newResponse(res.body, res);
  }
  console.error(err);
  return c.text("Internal Server Error", 500);
}, "errorHandler");
var Hono = /* @__PURE__ */ __name(class {
  get;
  post;
  put;
  delete;
  options;
  patch;
  all;
  on;
  use;
  router;
  getPath;
  _basePath = "/";
  #path = "/";
  routes = [];
  constructor(options = {}) {
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.forEach((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          this.#path = args1;
        } else {
          this.#addRoute(method, this.#path, args1);
        }
        args.forEach((handler) => {
          this.#addRoute(method, this.#path, handler);
        });
        return this;
      };
    });
    this.on = (method, path, ...handlers) => {
      for (const p of [path].flat()) {
        this.#path = p;
        for (const m of [method].flat()) {
          handlers.map((handler) => {
            this.#addRoute(m.toUpperCase(), this.#path, handler);
          });
        }
      }
      return this;
    };
    this.use = (arg1, ...handlers) => {
      if (typeof arg1 === "string") {
        this.#path = arg1;
      } else {
        this.#path = "*";
        handlers.unshift(arg1);
      }
      handlers.forEach((handler) => {
        this.#addRoute(METHOD_NAME_ALL, this.#path, handler);
      });
      return this;
    };
    const { strict, ...optionsWithoutStrict } = options;
    Object.assign(this, optionsWithoutStrict);
    this.getPath = strict ?? true ? options.getPath ?? getPath : getPathNoStrict;
  }
  #clone() {
    const clone = new Hono({
      router: this.router,
      getPath: this.getPath
    });
    clone.errorHandler = this.errorHandler;
    clone.#notFoundHandler = this.#notFoundHandler;
    clone.routes = this.routes;
    return clone;
  }
  #notFoundHandler = notFoundHandler;
  errorHandler = errorHandler;
  route(path, app15) {
    const subApp = this.basePath(path);
    app15.routes.map((r) => {
      let handler;
      if (app15.errorHandler === errorHandler) {
        handler = r.handler;
      } else {
        handler = /* @__PURE__ */ __name(async (c, next) => (await compose([], app15.errorHandler)(c, () => r.handler(c, next))).res, "handler");
        handler[COMPOSED_HANDLER] = r.handler;
      }
      subApp.#addRoute(r.method, r.path, handler);
    });
    return this;
  }
  basePath(path) {
    const subApp = this.#clone();
    subApp._basePath = mergePath(this._basePath, path);
    return subApp;
  }
  onError = (handler) => {
    this.errorHandler = handler;
    return this;
  };
  notFound = (handler) => {
    this.#notFoundHandler = handler;
    return this;
  };
  mount(path, applicationHandler, options) {
    let replaceRequest;
    let optionHandler;
    if (options) {
      if (typeof options === "function") {
        optionHandler = options;
      } else {
        optionHandler = options.optionHandler;
        if (options.replaceRequest === false) {
          replaceRequest = /* @__PURE__ */ __name((request) => request, "replaceRequest");
        } else {
          replaceRequest = options.replaceRequest;
        }
      }
    }
    const getOptions = optionHandler ? (c) => {
      const options2 = optionHandler(c);
      return Array.isArray(options2) ? options2 : [options2];
    } : (c) => {
      let executionContext = void 0;
      try {
        executionContext = c.executionCtx;
      } catch {
      }
      return [c.env, executionContext];
    };
    replaceRequest ||= (() => {
      const mergedPath = mergePath(this._basePath, path);
      const pathPrefixLength = mergedPath === "/" ? 0 : mergedPath.length;
      return (request) => {
        const url = new URL(request.url);
        url.pathname = url.pathname.slice(pathPrefixLength) || "/";
        return new Request(url, request);
      };
    })();
    const handler = /* @__PURE__ */ __name(async (c, next) => {
      const res = await applicationHandler(replaceRequest(c.req.raw), ...getOptions(c));
      if (res) {
        return res;
      }
      await next();
    }, "handler");
    this.#addRoute(METHOD_NAME_ALL, mergePath(path, "*"), handler);
    return this;
  }
  #addRoute(method, path, handler) {
    method = method.toUpperCase();
    path = mergePath(this._basePath, path);
    const r = { basePath: this._basePath, path, method, handler };
    this.router.add(method, path, [handler, r]);
    this.routes.push(r);
  }
  #handleError(err, c) {
    if (err instanceof Error) {
      return this.errorHandler(err, c);
    }
    throw err;
  }
  #dispatch(request, executionCtx, env, method) {
    if (method === "HEAD") {
      return (async () => new Response(null, await this.#dispatch(request, executionCtx, env, "GET")))();
    }
    const path = this.getPath(request, { env });
    const matchResult = this.router.match(method, path);
    const c = new Context(request, {
      path,
      matchResult,
      env,
      executionCtx,
      notFoundHandler: this.#notFoundHandler
    });
    if (matchResult[0].length === 1) {
      let res;
      try {
        res = matchResult[0][0][0][0](c, async () => {
          c.res = await this.#notFoundHandler(c);
        });
      } catch (err) {
        return this.#handleError(err, c);
      }
      return res instanceof Promise ? res.then(
        (resolved) => resolved || (c.finalized ? c.res : this.#notFoundHandler(c))
      ).catch((err) => this.#handleError(err, c)) : res ?? this.#notFoundHandler(c);
    }
    const composed = compose(matchResult[0], this.errorHandler, this.#notFoundHandler);
    return (async () => {
      try {
        const context = await composed(c);
        if (!context.finalized) {
          throw new Error(
            "Context is not finalized. Did you forget to return a Response object or `await next()`?"
          );
        }
        return context.res;
      } catch (err) {
        return this.#handleError(err, c);
      }
    })();
  }
  fetch = (request, ...rest) => {
    return this.#dispatch(request, rest[1], rest[0], request.method);
  };
  request = (input, requestInit, Env, executionCtx) => {
    if (input instanceof Request) {
      return this.fetch(requestInit ? new Request(input, requestInit) : input, Env, executionCtx);
    }
    input = input.toString();
    return this.fetch(
      new Request(
        /^https?:\/\//.test(input) ? input : `http://localhost${mergePath("/", input)}`,
        requestInit
      ),
      Env,
      executionCtx
    );
  };
  fire = () => {
    addEventListener("fetch", (event) => {
      event.respondWith(this.#dispatch(event.request, event, void 0, event.request.method));
    });
  };
}, "Hono");

// node_modules/hono/dist/router/reg-exp-router/matcher.js
var emptyParam = [];
function match(method, path) {
  const matchers = this.buildAllMatchers();
  const match2 = /* @__PURE__ */ __name((method2, path2) => {
    const matcher = matchers[method2] || matchers[METHOD_NAME_ALL];
    const staticMatch = matcher[2][path2];
    if (staticMatch) {
      return staticMatch;
    }
    const match3 = path2.match(matcher[0]);
    if (!match3) {
      return [[], emptyParam];
    }
    const index = match3.indexOf("", 1);
    return [matcher[1][index], match3];
  }, "match2");
  this.match = match2;
  return match2(method, path);
}
__name(match, "match");

// node_modules/hono/dist/router/reg-exp-router/node.js
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
var regExpMetaChars = new Set(".\\+*[^]$()");
function compareKey(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
}
__name(compareKey, "compareKey");
var Node = /* @__PURE__ */ __name(class {
  #index;
  #varIndex;
  #children = /* @__PURE__ */ Object.create(null);
  insert(tokens, index, paramMap, context, pathErrorCheckOnly) {
    if (tokens.length === 0) {
      if (this.#index !== void 0) {
        throw PATH_ERROR;
      }
      if (pathErrorCheckOnly) {
        return;
      }
      this.#index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      let regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      if (name && pattern[2]) {
        if (regexpStr === ".*") {
          throw PATH_ERROR;
        }
        regexpStr = regexpStr.replace(/^\((?!\?:)(?=[^)]+\)$)/, "(?:");
        if (/\((?!\?:)/.test(regexpStr)) {
          throw PATH_ERROR;
        }
      }
      node = this.#children[regexpStr];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[regexpStr] = new Node();
        if (name !== "") {
          node.#varIndex = context.varIndex++;
        }
      }
      if (!pathErrorCheckOnly && name !== "") {
        paramMap.push([name, node.#varIndex]);
      }
    } else {
      node = this.#children[token];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[token] = new Node();
      }
    }
    node.insert(restTokens, index, paramMap, context, pathErrorCheckOnly);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.#children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.#children[k];
      return (typeof c.#varIndex === "number" ? `(${k})@${c.#varIndex}` : regExpMetaChars.has(k) ? `\\${k}` : k) + c.buildRegExpStr();
    });
    if (typeof this.#index === "number") {
      strList.unshift(`#${this.#index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
}, "Node");

// node_modules/hono/dist/router/reg-exp-router/trie.js
var Trie = /* @__PURE__ */ __name(class {
  #context = { varIndex: 0 };
  #root = new Node();
  insert(path, index, pathErrorCheckOnly) {
    const paramAssoc = [];
    const groups = [];
    for (let i = 0; ; ) {
      let replaced = false;
      path = path.replace(/\{[^}]+\}/g, (m) => {
        const mark = `@\\${i}`;
        groups[i] = [mark, m];
        i++;
        replaced = true;
        return mark;
      });
      if (!replaced) {
        break;
      }
    }
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g) || [];
    for (let i = groups.length - 1; i >= 0; i--) {
      const [mark] = groups[i];
      for (let j = tokens.length - 1; j >= 0; j--) {
        if (tokens[j].indexOf(mark) !== -1) {
          tokens[j] = tokens[j].replace(mark, groups[i][1]);
          break;
        }
      }
    }
    this.#root.insert(tokens, index, paramAssoc, this.#context, pathErrorCheckOnly);
    return paramAssoc;
  }
  buildRegExp() {
    let regexp = this.#root.buildRegExpStr();
    if (regexp === "") {
      return [/^$/, [], []];
    }
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (handlerIndex !== void 0) {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (paramIndex !== void 0) {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
}, "Trie");

// node_modules/hono/dist/router/reg-exp-router/router.js
var nullMatcher = [/^$/, [], /* @__PURE__ */ Object.create(null)];
var wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
function buildWildcardRegExp(path) {
  return wildcardRegExpCache[path] ??= new RegExp(
    path === "*" ? "" : `^${path.replace(
      /\/\*$|([.\\+*[^\]$()])/g,
      (_, metaChar) => metaChar ? `\\${metaChar}` : "(?:|/.*)"
    )}$`
  );
}
__name(buildWildcardRegExp, "buildWildcardRegExp");
function clearWildcardRegExpCache() {
  wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
}
__name(clearWildcardRegExpCache, "clearWildcardRegExpCache");
function buildMatcherFromPreprocessedRoutes(routes) {
  const trie = new Trie();
  const handlerData = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  const routesWithStaticPathFlag = routes.map(
    (route) => [!/\*|\/:/.test(route[0]), ...route]
  ).sort(
    ([isStaticA, pathA], [isStaticB, pathB]) => isStaticA ? 1 : isStaticB ? -1 : pathA.length - pathB.length
  );
  const staticMap = /* @__PURE__ */ Object.create(null);
  for (let i = 0, j = -1, len = routesWithStaticPathFlag.length; i < len; i++) {
    const [pathErrorCheckOnly, path, handlers] = routesWithStaticPathFlag[i];
    if (pathErrorCheckOnly) {
      staticMap[path] = [handlers.map(([h]) => [h, /* @__PURE__ */ Object.create(null)]), emptyParam];
    } else {
      j++;
    }
    let paramAssoc;
    try {
      paramAssoc = trie.insert(path, j, pathErrorCheckOnly);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(path) : e;
    }
    if (pathErrorCheckOnly) {
      continue;
    }
    handlerData[j] = handlers.map(([h, paramCount]) => {
      const paramIndexMap = /* @__PURE__ */ Object.create(null);
      paramCount -= 1;
      for (; paramCount >= 0; paramCount--) {
        const [key, value] = paramAssoc[paramCount];
        paramIndexMap[key] = value;
      }
      return [h, paramIndexMap];
    });
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie.buildRegExp();
  for (let i = 0, len = handlerData.length; i < len; i++) {
    for (let j = 0, len2 = handlerData[i].length; j < len2; j++) {
      const map = handlerData[i][j]?.[1];
      if (!map) {
        continue;
      }
      const keys = Object.keys(map);
      for (let k = 0, len3 = keys.length; k < len3; k++) {
        map[keys[k]] = paramReplacementMap[map[keys[k]]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlerData[indexReplacementMap[i]];
  }
  return [regexp, handlerMap, staticMap];
}
__name(buildMatcherFromPreprocessedRoutes, "buildMatcherFromPreprocessedRoutes");
function findMiddleware(middleware, path) {
  if (!middleware) {
    return void 0;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return void 0;
}
__name(findMiddleware, "findMiddleware");
var RegExpRouter = /* @__PURE__ */ __name(class {
  name = "RegExpRouter";
  #middleware;
  #routes;
  constructor() {
    this.#middleware = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
    this.#routes = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
  }
  add(method, path, handler) {
    const middleware = this.#middleware;
    const routes = this.#routes;
    if (!middleware || !routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    if (!middleware[method]) {
      ;
      [middleware, routes].forEach((handlerMap) => {
        handlerMap[method] = /* @__PURE__ */ Object.create(null);
        Object.keys(handlerMap[METHOD_NAME_ALL]).forEach((p) => {
          handlerMap[method][p] = [...handlerMap[METHOD_NAME_ALL][p]];
        });
      });
    }
    if (path === "/*") {
      path = "*";
    }
    const paramCount = (path.match(/\/:/g) || []).length;
    if (/\*$/.test(path)) {
      const re = buildWildcardRegExp(path);
      if (method === METHOD_NAME_ALL) {
        Object.keys(middleware).forEach((m) => {
          middleware[m][path] ||= findMiddleware(middleware[m], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
        });
      } else {
        middleware[method][path] ||= findMiddleware(middleware[method], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
      }
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            re.test(p) && middleware[m][p].push([handler, paramCount]);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach(
            (p) => re.test(p) && routes[m][p].push([handler, paramCount])
          );
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length; i < len; i++) {
      const path2 = paths[i];
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          routes[m][path2] ||= [
            ...findMiddleware(middleware[m], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ];
          routes[m][path2].push([handler, paramCount - len + i + 1]);
        }
      });
    }
  }
  match = match;
  buildAllMatchers() {
    const matchers = /* @__PURE__ */ Object.create(null);
    Object.keys(this.#routes).concat(Object.keys(this.#middleware)).forEach((method) => {
      matchers[method] ||= this.#buildMatcher(method);
    });
    this.#middleware = this.#routes = void 0;
    clearWildcardRegExpCache();
    return matchers;
  }
  #buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.#middleware, this.#routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute ||= true;
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(
          ...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]])
        );
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
}, "RegExpRouter");

// node_modules/hono/dist/router/smart-router/router.js
var SmartRouter = /* @__PURE__ */ __name(class {
  name = "SmartRouter";
  #routers = [];
  #routes = [];
  constructor(init) {
    this.#routers = init.routers;
  }
  add(method, path, handler) {
    if (!this.#routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    this.#routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.#routes) {
      throw new Error("Fatal error");
    }
    const routers = this.#routers;
    const routes = this.#routes;
    const len = routers.length;
    let i = 0;
    let res;
    for (; i < len; i++) {
      const router = routers[i];
      try {
        for (let i2 = 0, len2 = routes.length; i2 < len2; i2++) {
          router.add(...routes[i2]);
        }
        res = router.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router.match.bind(router);
      this.#routers = [router];
      this.#routes = void 0;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    this.name = `SmartRouter + ${this.activeRouter.name}`;
    return res;
  }
  get activeRouter() {
    if (this.#routes || this.#routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.#routers[0];
  }
}, "SmartRouter");

// node_modules/hono/dist/router/trie-router/node.js
var emptyParams = /* @__PURE__ */ Object.create(null);
var Node2 = /* @__PURE__ */ __name(class {
  #methods;
  #children;
  #patterns;
  #order = 0;
  #params = emptyParams;
  constructor(method, handler, children) {
    this.#children = children || /* @__PURE__ */ Object.create(null);
    this.#methods = [];
    if (method && handler) {
      const m = /* @__PURE__ */ Object.create(null);
      m[method] = { handler, possibleKeys: [], score: 0 };
      this.#methods = [m];
    }
    this.#patterns = [];
  }
  insert(method, path, handler) {
    this.#order = ++this.#order;
    let curNode = this;
    const parts = splitRoutingPath(path);
    const possibleKeys = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const p = parts[i];
      const nextP = parts[i + 1];
      const pattern = getPattern(p, nextP);
      const key = Array.isArray(pattern) ? pattern[0] : p;
      if (key in curNode.#children) {
        curNode = curNode.#children[key];
        if (pattern) {
          possibleKeys.push(pattern[1]);
        }
        continue;
      }
      curNode.#children[key] = new Node2();
      if (pattern) {
        curNode.#patterns.push(pattern);
        possibleKeys.push(pattern[1]);
      }
      curNode = curNode.#children[key];
    }
    curNode.#methods.push({
      [method]: {
        handler,
        possibleKeys: possibleKeys.filter((v, i, a) => a.indexOf(v) === i),
        score: this.#order
      }
    });
    return curNode;
  }
  #getHandlerSets(node, method, nodeParams, params) {
    const handlerSets = [];
    for (let i = 0, len = node.#methods.length; i < len; i++) {
      const m = node.#methods[i];
      const handlerSet = m[method] || m[METHOD_NAME_ALL];
      const processedSet = {};
      if (handlerSet !== void 0) {
        handlerSet.params = /* @__PURE__ */ Object.create(null);
        handlerSets.push(handlerSet);
        if (nodeParams !== emptyParams || params && params !== emptyParams) {
          for (let i2 = 0, len2 = handlerSet.possibleKeys.length; i2 < len2; i2++) {
            const key = handlerSet.possibleKeys[i2];
            const processed = processedSet[handlerSet.score];
            handlerSet.params[key] = params?.[key] && !processed ? params[key] : nodeParams[key] ?? params?.[key];
            processedSet[handlerSet.score] = true;
          }
        }
      }
    }
    return handlerSets;
  }
  search(method, path) {
    const handlerSets = [];
    this.#params = emptyParams;
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    const curNodesQueue = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const part = parts[i];
      const isLast = i === len - 1;
      const tempNodes = [];
      for (let j = 0, len2 = curNodes.length; j < len2; j++) {
        const node = curNodes[j];
        const nextNode = node.#children[part];
        if (nextNode) {
          nextNode.#params = node.#params;
          if (isLast) {
            if (nextNode.#children["*"]) {
              handlerSets.push(
                ...this.#getHandlerSets(nextNode.#children["*"], method, node.#params)
              );
            }
            handlerSets.push(...this.#getHandlerSets(nextNode, method, node.#params));
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node.#patterns.length; k < len3; k++) {
          const pattern = node.#patterns[k];
          const params = node.#params === emptyParams ? {} : { ...node.#params };
          if (pattern === "*") {
            const astNode = node.#children["*"];
            if (astNode) {
              handlerSets.push(...this.#getHandlerSets(astNode, method, node.#params));
              astNode.#params = params;
              tempNodes.push(astNode);
            }
            continue;
          }
          const [key, name, matcher] = pattern;
          if (!part && !(matcher instanceof RegExp)) {
            continue;
          }
          const child = node.#children[key];
          const restPathString = parts.slice(i).join("/");
          if (matcher instanceof RegExp) {
            const m = matcher.exec(restPathString);
            if (m) {
              params[name] = m[0];
              handlerSets.push(...this.#getHandlerSets(child, method, node.#params, params));
              if (Object.keys(child.#children).length) {
                child.#params = params;
                const componentCount = m[0].match(/\//)?.length ?? 0;
                const targetCurNodes = curNodesQueue[componentCount] ||= [];
                targetCurNodes.push(child);
              }
              continue;
            }
          }
          if (matcher === true || matcher.test(part)) {
            params[name] = part;
            if (isLast) {
              handlerSets.push(...this.#getHandlerSets(child, method, params, node.#params));
              if (child.#children["*"]) {
                handlerSets.push(
                  ...this.#getHandlerSets(child.#children["*"], method, params, node.#params)
                );
              }
            } else {
              child.#params = params;
              tempNodes.push(child);
            }
          }
        }
      }
      curNodes = tempNodes.concat(curNodesQueue.shift() ?? []);
    }
    if (handlerSets.length > 1) {
      handlerSets.sort((a, b) => {
        return a.score - b.score;
      });
    }
    return [handlerSets.map(({ handler, params }) => [handler, params])];
  }
}, "Node");

// node_modules/hono/dist/router/trie-router/router.js
var TrieRouter = /* @__PURE__ */ __name(class {
  name = "TrieRouter";
  #node;
  constructor() {
    this.#node = new Node2();
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (let i = 0, len = results.length; i < len; i++) {
        this.#node.insert(method, results[i], handler);
      }
      return;
    }
    this.#node.insert(method, path, handler);
  }
  match(method, path) {
    return this.#node.search(method, path);
  }
}, "TrieRouter");

// node_modules/hono/dist/hono.js
var Hono2 = /* @__PURE__ */ __name(class extends Hono {
  constructor(options = {}) {
    super(options);
    this.router = options.router ?? new SmartRouter({
      routers: [new RegExpRouter(), new TrieRouter()]
    });
  }
}, "Hono");

// node_modules/hono/dist/middleware/cors/index.js
var cors = /* @__PURE__ */ __name((options) => {
  const defaults = {
    origin: "*",
    allowMethods: ["GET", "HEAD", "PUT", "POST", "DELETE", "PATCH"],
    allowHeaders: [],
    exposeHeaders: []
  };
  const opts = {
    ...defaults,
    ...options
  };
  const findAllowOrigin = ((optsOrigin) => {
    if (typeof optsOrigin === "string") {
      if (optsOrigin === "*") {
        return () => optsOrigin;
      } else {
        return (origin) => optsOrigin === origin ? origin : null;
      }
    } else if (typeof optsOrigin === "function") {
      return optsOrigin;
    } else {
      return (origin) => optsOrigin.includes(origin) ? origin : null;
    }
  })(opts.origin);
  const findAllowMethods = ((optsAllowMethods) => {
    if (typeof optsAllowMethods === "function") {
      return optsAllowMethods;
    } else if (Array.isArray(optsAllowMethods)) {
      return () => optsAllowMethods;
    } else {
      return () => [];
    }
  })(opts.allowMethods);
  return /* @__PURE__ */ __name(async function cors2(c, next) {
    function set(key, value) {
      c.res.headers.set(key, value);
    }
    __name(set, "set");
    const allowOrigin = await findAllowOrigin(c.req.header("origin") || "", c);
    if (allowOrigin) {
      set("Access-Control-Allow-Origin", allowOrigin);
    }
    if (opts.origin !== "*") {
      const existingVary = c.req.header("Vary");
      if (existingVary) {
        set("Vary", existingVary);
      } else {
        set("Vary", "Origin");
      }
    }
    if (opts.credentials) {
      set("Access-Control-Allow-Credentials", "true");
    }
    if (opts.exposeHeaders?.length) {
      set("Access-Control-Expose-Headers", opts.exposeHeaders.join(","));
    }
    if (c.req.method === "OPTIONS") {
      if (opts.maxAge != null) {
        set("Access-Control-Max-Age", opts.maxAge.toString());
      }
      const allowMethods = await findAllowMethods(c.req.header("origin") || "", c);
      if (allowMethods.length) {
        set("Access-Control-Allow-Methods", allowMethods.join(","));
      }
      let headers = opts.allowHeaders;
      if (!headers?.length) {
        const requestHeaders = c.req.header("Access-Control-Request-Headers");
        if (requestHeaders) {
          headers = requestHeaders.split(/\s*,\s*/);
        }
      }
      if (headers?.length) {
        set("Access-Control-Allow-Headers", headers.join(","));
        c.res.headers.append("Vary", "Access-Control-Request-Headers");
      }
      c.res.headers.delete("Content-Length");
      c.res.headers.delete("Content-Type");
      return new Response(null, {
        headers: c.res.headers,
        status: 204,
        statusText: "No Content"
      });
    }
    await next();
  }, "cors2");
}, "cors");

// src/handlers/auth.js
init_auth();
init_jwt();
var app = new Hono2();
app.post("/signin", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    if (!body.username || !body.password) {
      return errorResponse("Username and password are required", 400);
    }
    await cleanupExpiredSessions(db);
    const stmt = db.prepare(`
      SELECT id, username, nickname, password_hash, email, is_admin, role, row_status
      FROM users
      WHERE username = ?
    `);
    const user = await stmt.bind(body.username).first();
    if (!user) {
      return errorResponse("Invalid username or password", 401);
    }
    const isValidPassword = await verifyPassword(body.password, user.password_hash);
    if (!isValidPassword) {
      return errorResponse("Invalid username or password", 401);
    }
    if (needsPasswordUpgrade(user.password_hash)) {
      console.log(`Upgrading password hash for user ${user.username}`);
      const newHash = await hashPassword(body.password);
      await upgradePasswordHash(db, user.id, newHash);
    }
    const roleMap = { "host": 1, "admin": 2, "user": 3 };
    const roleValue = roleMap[user.role] || 3;
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: user.id,
      username: user.username,
      nickname: user.nickname,
      email: user.email || "",
      role: roleValue
    }, jwtSecret);
    return jsonResponse({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        name: `users/${user.username}`,
        username: user.username,
        nickname: user.nickname,
        email: user.email || "",
        avatarUrl: "",
        role: roleValue,
        rowStatus: user.row_status || 0
      },
      token
    });
  } catch (error) {
    console.error("Error during signin:", error);
    return errorResponse("Login failed", 500);
  }
});
app.post("/signup", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    if (!body.username || !body.nickname || !body.password) {
      return errorResponse("Username, nickname and password are required", 400);
    }
    if (body.password.length < 6) {
      return errorResponse("Password must be at least 6 characters long", 400);
    }
    const userCountStmt = db.prepare("SELECT COUNT(*) as count FROM users");
    const userCount = await userCountStmt.first();
    const isFirstUser = userCount.count === 0;
    if (!isFirstUser) {
      const settingStmt = db.prepare("SELECT value FROM settings WHERE key = 'allow_registration'");
      const setting = await settingStmt.first();
      if (setting && setting.value === "false") {
        return errorResponse("Registration is currently disabled", 403);
      }
    }
    const existingUserStmt = db.prepare("SELECT id FROM users WHERE username = ?");
    const existingUser = await existingUserStmt.bind(body.username).first();
    if (existingUser) {
      return errorResponse("Username already exists", 400);
    }
    const hashedPassword = await hashPassword(body.password);
    const userRole = isFirstUser ? "host" : "user";
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
    const roleMap = { "host": 1, "admin": 2, "user": 3 };
    const roleValue = roleMap[userRole] || 3;
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: result.meta.last_row_id,
      username: body.username,
      nickname: body.nickname,
      email: body.email || "",
      role: roleValue
    }, jwtSecret);
    return jsonResponse({
      success: true,
      message: isFirstUser ? "First user created as host" : "User created successfully",
      user: {
        id: result.meta.last_row_id,
        name: `users/${body.username}`,
        username: body.username,
        nickname: body.nickname,
        email: body.email || "",
        avatarUrl: "",
        role: roleValue,
        rowStatus: 0
        // 新创建的用户默认 rowStatus 为 0
      },
      token
    }, 201);
  } catch (error) {
    console.error("Error during signup:", error);
    return errorResponse("Registration failed", 500);
  }
});
app.post("/signout", async (c) => {
  try {
    const db = c.env.DB;
    const authHeader = c.req.header("Authorization");
    const token = authHeader?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    if (token && /^[0-9a-f]{64}$/.test(token)) {
      await deleteSession(db, token);
    }
    return jsonResponse({
      success: true,
      message: "Logout successful"
    });
  } catch (error) {
    console.error("Error during signout:", error);
    return errorResponse("Logout failed", 500);
  }
});
app.get("/status", async (c) => {
  try {
    const db = c.env.DB;
    const authHeader = c.req.header("Authorization");
    const token = authHeader?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    if (!token) {
      return jsonResponse({
        authenticated: false,
        user: null
      });
    }
    const { verifyJWT: verifyJWT2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
    const jwtSecret = getJWTSecret(c.env);
    const payload = await verifyJWT2(token, jwtSecret);
    if (!payload) {
      return jsonResponse({
        authenticated: false,
        user: null
      });
    }
    const userStmt = db.prepare(`
      SELECT id, username, nickname, email, avatar_url, is_admin, role, row_status
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
    const roleMap = { "host": 1, "admin": 2, "user": 3 };
    const roleValue = roleMap[dbUser.role] || 3;
    return jsonResponse({
      authenticated: true,
      user: {
        id: dbUser.id,
        name: `users/${dbUser.username}`,
        username: dbUser.username,
        nickname: dbUser.nickname,
        email: dbUser.email || "",
        avatarUrl: dbUser.avatar_url || "",
        role: roleValue,
        rowStatus: dbUser.row_status || 0
      }
    });
  } catch (error) {
    console.error("Error checking auth status:", error);
    return jsonResponse({
      authenticated: false,
      user: null
    });
  }
});
app.post("/signin/sso", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    console.log("=== SSO Login Request ===");
    console.log("Request body:", JSON.stringify(body));
    if (!body.identityProviderId || !body.code || !body.redirectUri) {
      console.error("Missing required parameters");
      return errorResponse("identityProviderId, code and redirectUri are required", 400);
    }
    const idpStmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config
      FROM identity_providers
      WHERE id = ?
    `);
    const idp = await idpStmt.bind(body.identityProviderId).first();
    if (!idp) {
      console.error("Identity provider not found:", body.identityProviderId);
      return errorResponse("Identity provider not found", 404);
    }
    console.log("IDP found:", idp.name, "Type:", idp.type);
    let config;
    try {
      config = JSON.parse(idp.config);
      console.log("Config parsed successfully");
    } catch (e) {
      console.error("Failed to parse IDP config:", e);
      return errorResponse("Invalid identity provider configuration", 500);
    }
    let oauth2Config = config;
    if (config.oauth2Config) {
      oauth2Config = config.oauth2Config;
      console.log("Using nested oauth2Config");
    }
    let tokenResponse;
    try {
      const tokenUrl = getTokenUrl(idp.type, oauth2Config);
      console.log("Exchanging code for token at:", tokenUrl);
      console.log("IDP type:", idp.type);
      console.log("Config has tokenUrl:", !!oauth2Config.tokenUrl);
      const tokenParams = new URLSearchParams({
        client_id: oauth2Config.clientId,
        client_secret: oauth2Config.clientSecret,
        code: body.code,
        redirect_uri: body.redirectUri,
        grant_type: "authorization_code"
      });
      const response = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json"
        },
        body: tokenParams
      });
      console.log("Token exchange response status:", response.status);
      if (!response.ok) {
        const errorText = await response.text();
        console.error("Token exchange failed with status:", response.status);
        console.error("Error response:", errorText);
        return errorResponse("Failed to exchange authorization code", 401);
      }
      tokenResponse = await response.json();
      console.log("Token response received:", JSON.stringify(tokenResponse));
      console.log("Token response received, has access_token:", !!tokenResponse.access_token);
    } catch (error) {
      console.error("Error exchanging code for token:", error);
      console.error("Error stack:", error.stack);
      return errorResponse("Failed to authenticate with identity provider", 500);
    }
    let userInfo;
    try {
      const userInfoUrl = getUserInfoUrl(idp.type, oauth2Config);
      console.log("Fetching user info from:", userInfoUrl);
      console.log("Using access token:", tokenResponse.access_token?.substring(0, 20) + "...");
      const userInfoResponse = await fetch(userInfoUrl, {
        headers: {
          "Authorization": `Bearer ${tokenResponse.access_token}`,
          "Accept": "application/json",
          "User-Agent": "Memos-SSO-Client/1.0"
          // GitHub API 要求 User-Agent
        }
      });
      console.log("User info response status:", userInfoResponse.status);
      if (!userInfoResponse.ok) {
        const errorText = await userInfoResponse.text();
        console.error("User info request failed with status:", userInfoResponse.status);
        console.error("Error response:", errorText);
        return errorResponse(`Failed to get user information: ${userInfoResponse.status} - ${errorText.substring(0, 200)}`, 401);
      }
      userInfo = await userInfoResponse.json();
      console.log("User info received:", JSON.stringify(userInfo).substring(0, 200));
      if (idp.type === "OAUTH2" && (!userInfo.email || userInfo.email === null)) {
        console.log("Email not found in user info, checking if GitHub...");
        if (userInfoUrl.includes("api.github.com")) {
          console.log("Detected GitHub, fetching emails from /user/emails");
          try {
            const emailsResponse = await fetch("https://api.github.com/user/emails", {
              headers: {
                "Authorization": `Bearer ${tokenResponse.access_token}`,
                "Accept": "application/json",
                "User-Agent": "Memos-SSO-Client/1.0"
                // GitHub API 要求 User-Agent
              }
            });
            console.log("GitHub emails response status:", emailsResponse.status);
            if (emailsResponse.ok) {
              const emails = await emailsResponse.json();
              console.log("GitHub emails response:", JSON.stringify(emails));
              const primaryEmail = emails.find((e) => e.primary);
              if (primaryEmail) {
                userInfo.email = primaryEmail.email;
                console.log("Using primary email:", userInfo.email);
              } else if (emails.length > 0) {
                userInfo.email = emails[0].email;
                console.log("Using first email:", userInfo.email);
              }
            } else {
              const emailError = await emailsResponse.text();
              console.error("Failed to fetch GitHub emails:", emailsResponse.status, emailError);
            }
          } catch (emailError) {
            console.error("Failed to fetch GitHub emails:", emailError);
          }
        }
      }
    } catch (error) {
      console.error("Error getting user info:", error);
      console.error("Error stack:", error.stack);
      return errorResponse(`Failed to get user information from identity provider: ${error.message}`, 500);
    }
    const email = getUserEmail(idp.type, userInfo, oauth2Config);
    const username = getUserUsername(idp.type, userInfo, oauth2Config);
    const nickname = getUserNickname(idp.type, userInfo, oauth2Config);
    if (!username) {
      return errorResponse("Username is required for SSO login", 400);
    }
    if (idp.identifier_filter && email) {
      const allowedDomains = idp.identifier_filter.split(",").map((d) => d.trim());
      const emailDomain = email.split("@")[1];
      if (!allowedDomains.includes(emailDomain)) {
        return errorResponse(`Email domain ${emailDomain} is not allowed for this identity provider`, 403);
      }
    }
    let user;
    const userStmt = db.prepare("SELECT * FROM users WHERE username = ?");
    user = await userStmt.bind(username).first();
    if (!user) {
      const hashedPassword = await hashPassword(Math.random().toString(36));
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
      user = await db.prepare("SELECT * FROM users WHERE id = ?").bind(result.meta.last_row_id).first();
      console.log("Created new user via SSO:", username);
    } else {
      console.log("Found existing user via SSO:", username);
    }
    const roleMap = { "host": 1, "admin": 2, "user": 3 };
    const roleValue = roleMap[user.role] || 3;
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: user.id,
      username: user.username,
      nickname: user.nickname,
      email: user.email || "",
      role: roleValue
    }, jwtSecret);
    return jsonResponse({
      success: true,
      message: "SSO login successful",
      user: {
        id: user.id,
        name: `users/${user.username}`,
        username: user.username,
        nickname: user.nickname,
        email: user.email || "",
        avatarUrl: user.avatar_url || "",
        role: roleValue,
        rowStatus: user.row_status || 0
      },
      token
    });
  } catch (error) {
    console.error("Error during SSO signin:", error);
    console.error("Error message:", error.message);
    console.error("Error stack:", error.stack);
    return errorResponse(`SSO login failed: ${error.message}`, 500);
  }
});
function getTokenUrl(type, config) {
  if (type === "OAUTH2") {
    return config.tokenUrl;
  }
  const urls = {
    "google": "https://oauth2.googleapis.com/token",
    "github": "https://github.com/login/oauth/access_token",
    "gitlab": `${config.instanceUrl || "https://gitlab.com"}/oauth/token`,
    "oidc": config.tokenUrl
  };
  return urls[type] || config.tokenUrl;
}
__name(getTokenUrl, "getTokenUrl");
function getUserInfoUrl(type, config) {
  if (type === "OAUTH2") {
    return config.userInfoUrl;
  }
  const urls = {
    "google": "https://www.googleapis.com/oauth2/v2/userinfo",
    "github": "https://api.github.com/user",
    "gitlab": `${config.instanceUrl || "https://gitlab.com"}/api/v4/user`,
    "oidc": config.userInfoUrl
  };
  return urls[type] || config.userInfoUrl;
}
__name(getUserInfoUrl, "getUserInfoUrl");
function getUserEmail(type, userInfo, config) {
  if (config.fieldMapping && config.fieldMapping.email) {
    return userInfo[config.fieldMapping.email];
  }
  if (type === "OAUTH2") {
    return userInfo.email;
  }
  if (type === "google")
    return userInfo.email;
  if (type === "github")
    return userInfo.email;
  if (type === "gitlab")
    return userInfo.email;
  return userInfo.email;
}
__name(getUserEmail, "getUserEmail");
function getUserUsername(type, userInfo, config) {
  if (config.fieldMapping && config.fieldMapping.identifier) {
    return userInfo[config.fieldMapping.identifier];
  }
  if (type === "OAUTH2") {
    return userInfo.login || userInfo.username || userInfo.preferred_username || userInfo.email?.split("@")[0];
  }
  if (type === "google")
    return userInfo.email?.split("@")[0];
  if (type === "github")
    return userInfo.login;
  if (type === "gitlab")
    return userInfo.username;
  return userInfo.preferred_username || userInfo.email?.split("@")[0];
}
__name(getUserUsername, "getUserUsername");
function getUserNickname(type, userInfo, config) {
  if (config.fieldMapping && config.fieldMapping.displayName) {
    return userInfo[config.fieldMapping.displayName];
  }
  if (type === "OAUTH2") {
    return userInfo.name || userInfo.display_name || userInfo.nickname || userInfo.login || userInfo.username;
  }
  if (type === "google")
    return userInfo.name;
  if (type === "github")
    return userInfo.name || userInfo.login;
  if (type === "gitlab")
    return userInfo.name;
  return userInfo.name || userInfo.preferred_username;
}
__name(getUserNickname, "getUserNickname");
var auth_default = app;

// src/handlers/memos.js
init_auth();

// src/utils/gravatar.js
function simpleMD5(str) {
  function safeAdd(x, y) {
    const lsw = (x & 65535) + (y & 65535);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return msw << 16 | lsw & 65535;
  }
  __name(safeAdd, "safeAdd");
  function bitRotateLeft(num, cnt) {
    return num << cnt | num >>> 32 - cnt;
  }
  __name(bitRotateLeft, "bitRotateLeft");
  function md5cmn(q, a, b, x, s, t) {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }
  __name(md5cmn, "md5cmn");
  function md5ff(a, b, c, d, x, s, t) {
    return md5cmn(b & c | ~b & d, a, b, x, s, t);
  }
  __name(md5ff, "md5ff");
  function md5gg(a, b, c, d, x, s, t) {
    return md5cmn(b & d | c & ~d, a, b, x, s, t);
  }
  __name(md5gg, "md5gg");
  function md5hh(a, b, c, d, x, s, t) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }
  __name(md5hh, "md5hh");
  function md5ii(a, b, c, d, x, s, t) {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }
  __name(md5ii, "md5ii");
  function binlMD5(x, len) {
    x[len >> 5] |= 128 << len % 32;
    x[(len + 64 >>> 9 << 4) + 14] = len;
    let i;
    let olda;
    let oldb;
    let oldc;
    let oldd;
    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;
    for (i = 0; i < x.length; i += 16) {
      olda = a;
      oldb = b;
      oldc = c;
      oldd = d;
      a = md5ff(a, b, c, d, x[i], 7, -680876936);
      d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
      c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
      b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
      a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
      d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
      c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
      b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
      a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
      d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
      c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
      b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
      a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
      d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
      c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
      b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
      a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
      d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
      c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
      b = md5gg(b, c, d, a, x[i], 20, -373897302);
      a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
      d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
      c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
      b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
      a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
      d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
      c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
      b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
      a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
      d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
      c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
      b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
      a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
      d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
      c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
      b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
      a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
      d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
      c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
      b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
      a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
      d = md5hh(d, a, b, c, x[i], 11, -358537222);
      c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
      b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
      a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
      d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
      c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
      b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
      a = md5ii(a, b, c, d, x[i], 6, -198630844);
      d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
      c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
      b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
      a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
      d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
      c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
      b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
      a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
      d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
      c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
      b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
      a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
      d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
      c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
      b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
      a = safeAdd(a, olda);
      b = safeAdd(b, oldb);
      c = safeAdd(c, oldc);
      d = safeAdd(d, oldd);
    }
    return [a, b, c, d];
  }
  __name(binlMD5, "binlMD5");
  function binl2hex(binarray) {
    const hexTab = "0123456789abcdef";
    let str2 = "";
    for (let i = 0; i < binarray.length * 4; i++) {
      str2 += hexTab.charAt(binarray[i >> 2] >> i % 4 * 8 + 4 & 15) + hexTab.charAt(binarray[i >> 2] >> i % 4 * 8 & 15);
    }
    return str2;
  }
  __name(binl2hex, "binl2hex");
  function str2binl(str2) {
    const bin = [];
    const mask = (1 << 8) - 1;
    for (let i = 0; i < str2.length * 8; i += 8) {
      bin[i >> 5] |= (str2.charCodeAt(i / 8) & mask) << i % 32;
    }
    return bin;
  }
  __name(str2binl, "str2binl");
  function utf8Encode(str2) {
    return unescape(encodeURIComponent(str2));
  }
  __name(utf8Encode, "utf8Encode");
  const utf8String = utf8Encode(str);
  return binl2hex(binlMD5(str2binl(utf8String), utf8String.length * 8));
}
__name(simpleMD5, "simpleMD5");

// src/utils/telegram.js
function buildTelegramApiUrl(botTokenOrBaseUrl, method) {
  const rawValue = typeof botTokenOrBaseUrl === "string" ? botTokenOrBaseUrl.trim() : "";
  if (!rawValue) {
    return null;
  }
  const normalizedMethod = typeof method === "string" ? method.trim().replace(/^\/+/, "") : "";
  if (!normalizedMethod) {
    return null;
  }
  if (/^https?:\/\//i.test(rawValue)) {
    return `${rawValue.replace(/\/+$/, "")}/${normalizedMethod}`;
  }
  const normalizedToken = rawValue.startsWith("bot") ? rawValue.slice(3) : rawValue;
  return `https://api.telegram.org/bot${normalizedToken}/${normalizedMethod}`;
}
__name(buildTelegramApiUrl, "buildTelegramApiUrl");
async function callTelegramApi(botTokenOrBaseUrl, method, payload) {
  const telegramApiUrl = buildTelegramApiUrl(botTokenOrBaseUrl, method);
  if (!telegramApiUrl) {
    throw new Error("Telegram bot token is not configured");
  }
  const response = await fetch(telegramApiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  let result = null;
  try {
    result = await response.json();
  } catch (error) {
    throw new Error(`Telegram API ${method} returned a non-JSON response`);
  }
  if (!response.ok || result?.ok === false) {
    const description = result?.description || `${response.status} ${response.statusText}`;
    throw new Error(`Telegram API ${method} failed: ${description}`);
  }
  return result;
}
__name(callTelegramApi, "callTelegramApi");
async function sendTelegramText(botTokenOrBaseUrl, chatId, text, extraPayload = {}) {
  return callTelegramApi(botTokenOrBaseUrl, "sendMessage", {
    chat_id: chatId,
    text,
    ...extraPayload
  });
}
__name(sendTelegramText, "sendTelegramText");

// src/utils/notifications.js
var TELEGRAM_MEMO_PREVIEW_LIMIT = 3800;
var TELEGRAM_VISIBILITY_OPTIONS = ["PRIVATE", "PROTECTED", "PUBLIC"];
var TELEGRAM_VISIBILITY_LABELS = {
  PRIVATE: "\u79C1\u5BC6",
  PROTECTED: "\u53D7\u4FDD\u62A4",
  PUBLIC: "\u516C\u5F00"
};
function truncateTelegramText(text) {
  if (text.length <= TELEGRAM_MEMO_PREVIEW_LIMIT) {
    return text;
  }
  return `${text.slice(0, TELEGRAM_MEMO_PREVIEW_LIMIT)}
...`;
}
__name(truncateTelegramText, "truncateTelegramText");
function getTelegramMemoContent(memoData) {
  const content = typeof memoData?.content === "string" ? memoData.content.trim() : "";
  if (content) {
    return truncateTelegramText(content);
  }
  if ((memoData?.resourceCount || 0) > 0) {
    return `\u{1F4CE} \u6B64 memo \u4EC5\u5305\u542B ${memoData.resourceCount} \u4E2A\u9644\u4EF6`;
  }
  return "\uFF08\u65E0\u6587\u672C\u5185\u5BB9\uFF09";
}
__name(getTelegramMemoContent, "getTelegramMemoContent");
function getTelegramVisibilityLabel(visibility) {
  return TELEGRAM_VISIBILITY_LABELS[visibility] || visibility || "\u672A\u77E5";
}
__name(getTelegramVisibilityLabel, "getTelegramVisibilityLabel");
function buildTelegramMemoVisibilityCallbackData(memoId, visibility) {
  return `memo_visibility:${memoId}:${visibility}`;
}
__name(buildTelegramMemoVisibilityCallbackData, "buildTelegramMemoVisibilityCallbackData");
function parseTelegramMemoVisibilityCallbackData(data) {
  if (typeof data !== "string") {
    return null;
  }
  const matched = data.match(/^memo_visibility:(\d+):(PRIVATE|PROTECTED|PUBLIC)$/);
  if (!matched) {
    return null;
  }
  return {
    memoId: Number.parseInt(matched[1], 10),
    visibility: matched[2]
  };
}
__name(parseTelegramMemoVisibilityCallbackData, "parseTelegramMemoVisibilityCallbackData");
function buildTelegramMemoNotificationText(memoData) {
  return getTelegramMemoContent(memoData);
}
__name(buildTelegramMemoNotificationText, "buildTelegramMemoNotificationText");
function buildTelegramMemoReplyMarkup(memoData, instanceUrl) {
  const inlineKeyboard = [
    TELEGRAM_VISIBILITY_OPTIONS.map((visibility) => ({
      text: memoData.visibility === visibility ? `\u25CF ${getTelegramVisibilityLabel(visibility)}` : getTelegramVisibilityLabel(visibility),
      callback_data: buildTelegramMemoVisibilityCallbackData(memoData.id, visibility)
    }))
  ];
  if (instanceUrl) {
    inlineKeyboard.push([
      {
        text: "\u6253\u5F00 Memo",
        url: `${instanceUrl}/m/${memoData.id}`
      }
    ]);
  }
  return {
    inline_keyboard: inlineKeyboard
  };
}
__name(buildTelegramMemoReplyMarkup, "buildTelegramMemoReplyMarkup");
async function sendWebhook(webhookUrl, memoData) {
  if (!webhookUrl || webhookUrl.trim() === "") {
    return;
  }
  try {
    const payload = {
      event: "memo.created",
      timestamp: Date.now(),
      data: {
        id: memoData.id,
        content: memoData.content,
        visibility: memoData.visibility,
        creator: {
          id: memoData.creatorId,
          username: memoData.creatorUsername,
          name: memoData.creatorName
        },
        createdTs: memoData.createdTs,
        tags: memoData.tags || [],
        resourceCount: memoData.resourceCount || 0
      }
    };
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Cloudflare-Memos-Webhook/1.0"
      },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      console.error(`Webhook failed: ${response.status} ${response.statusText}`);
    } else {
      console.log("Webhook sent successfully");
    }
  } catch (error) {
    console.error("Error sending webhook:", error);
  }
}
__name(sendWebhook, "sendWebhook");
async function sendTelegramNotification(botToken, chatId, memoData, instanceUrl) {
  if (!botToken || botToken.trim() === "" || !chatId || chatId.trim() === "") {
    return;
  }
  try {
    const message = buildTelegramMemoNotificationText(memoData);
    const result = await callTelegramApi(botToken, "sendMessage", {
      chat_id: chatId,
      text: message,
      disable_web_page_preview: true,
      reply_markup: buildTelegramMemoReplyMarkup(memoData, instanceUrl)
    });
    if (!result.ok) {
      console.error("Telegram notification failed:", result);
    } else {
      console.log("Telegram notification sent successfully");
    }
  } catch (error) {
    console.error("Error sending Telegram notification:", error);
  }
}
__name(sendTelegramNotification, "sendTelegramNotification");
async function editTelegramMemoNotification(botToken, chatId, messageId, memoData, instanceUrl) {
  if (!botToken || !chatId || !messageId) {
    return;
  }
  return callTelegramApi(botToken, "editMessageText", {
    chat_id: chatId,
    message_id: messageId,
    text: buildTelegramMemoNotificationText(memoData),
    disable_web_page_preview: true,
    reply_markup: buildTelegramMemoReplyMarkup(memoData, instanceUrl)
  });
}
__name(editTelegramMemoNotification, "editTelegramMemoNotification");
async function answerTelegramCallback(botToken, callbackQueryId, text, showAlert = false) {
  if (!botToken || !callbackQueryId) {
    return;
  }
  return callTelegramApi(botToken, "answerCallbackQuery", {
    callback_query_id: callbackQueryId,
    text,
    show_alert: showAlert
  });
}
__name(answerTelegramCallback, "answerTelegramCallback");
async function sendAllNotifications(db, memoData, options = {}) {
  console.log("\u{1F514} sendAllNotifications called for memo:", memoData.id);
  try {
    const userSettingStmt = db.prepare(`
      SELECT telegram_user_id
      FROM user_settings
      WHERE user_id = ?
    `);
    const userSetting = await userSettingStmt.bind(memoData.creatorId).first();
    console.log("\u{1F464} User settings:", { userId: memoData.creatorId, telegramUserId: userSetting?.telegram_user_id });
    const webhooksStmt = db.prepare(`
      SELECT url
      FROM webhooks
      WHERE user_id = ?
    `);
    const { results: webhooks } = await webhooksStmt.bind(memoData.creatorId).all();
    console.log("\u{1F517} Webhooks found:", webhooks?.length || 0);
    const settingsStmt = db.prepare(`
      SELECT key, value
      FROM settings
      WHERE key IN ('telegram-bot-token', 'instance-url')
    `);
    const { results: settings } = await settingsStmt.all();
    const settingsMap = {};
    settings.forEach((s) => {
      settingsMap[s.key] = s.value;
    });
    const telegramBotToken = settingsMap["telegram-bot-token"];
    const instanceUrl = settingsMap["instance-url"];
    console.log("\u2699\uFE0F  System settings:", {
      hasBotToken: !!telegramBotToken,
      botTokenPrefix: telegramBotToken?.substring(0, 10) + "...",
      instanceUrl
    });
    const telegramUserId = userSetting?.telegram_user_id;
    const promises = [];
    if (webhooks && webhooks.length > 0) {
      webhooks.forEach((webhook) => {
        if (webhook.url) {
          console.log("\u{1F4E4} Adding webhook to queue:", webhook.url);
          promises.push(sendWebhook(webhook.url, memoData));
        }
      });
    }
    if (!options.skipTelegram && telegramBotToken && telegramUserId) {
      console.log("\u{1F4F1} Adding Telegram notification to queue for user:", telegramUserId);
      promises.push(sendTelegramNotification(telegramBotToken, telegramUserId, memoData, instanceUrl));
    } else {
      console.log("\u26A0\uFE0F  Telegram notification not queued:", {
        skipTelegram: Boolean(options.skipTelegram),
        hasBotToken: !!telegramBotToken,
        hasTelegramUserId: !!telegramUserId
      });
    }
    if (promises.length > 0) {
      console.log(`\u{1F680} Sending ${promises.length} notification(s)...`);
      const results = await Promise.allSettled(promises);
      console.log("\u2705 All notifications processed:", results.map((r) => r.status));
    } else {
      console.log("\u26A0\uFE0F  No notification endpoints configured for this user");
    }
  } catch (error) {
    console.error("Error in sendAllNotifications:", error);
  }
}
__name(sendAllNotifications, "sendAllNotifications");

// src/utils/tags.js
var cachedTagSchemaPromise = null;
var CODE_BLOCK_REG = /```[\s\S]*?```/g;
var INLINE_CODE_REG = /`[^`\n]*`/g;
var MARKDOWN_LINK_REG = /!?\[[^\]]*\]\([^)]+\)/g;
var PLAIN_LINK_REG = /(?:https?|chrome|edge):\/\/\S+/g;
var TAG_NAME_REG = /(^|[\s(\[{"'“‘（【《「『<,.;:!?，。！？；：、])#([^\s#,]+)/g;
function buildTagSelectColumns(schema) {
  return [
    "id",
    "name",
    schema.hasCreatorId ? "creator_id as creatorId" : "NULL as creatorId",
    schema.hasCreatedTs ? "created_ts as createdTs" : "NULL as createdTs"
  ].join(", ");
}
__name(buildTagSelectColumns, "buildTagSelectColumns");
async function loadTagSchema(db) {
  const { results } = await db.prepare("PRAGMA table_info(tags)").all();
  const columns = new Set((results || []).map((column) => column.name));
  return {
    hasCreatorId: columns.has("creator_id"),
    hasCreatedTs: columns.has("created_ts")
  };
}
__name(loadTagSchema, "loadTagSchema");
async function getTagById(db, id, schema) {
  const stmt = db.prepare(`
    SELECT ${buildTagSelectColumns(schema)}
    FROM tags
    WHERE id = ?
  `);
  return stmt.bind(id).first();
}
__name(getTagById, "getTagById");
async function getTagSchema(db) {
  if (!cachedTagSchemaPromise) {
    cachedTagSchemaPromise = loadTagSchema(db).catch((error) => {
      cachedTagSchemaPromise = null;
      throw error;
    });
  }
  return cachedTagSchemaPromise;
}
__name(getTagSchema, "getTagSchema");
function stripIgnoredTagSegments(content = "") {
  return content.replace(CODE_BLOCK_REG, " ").replace(INLINE_CODE_REG, " ").replace(MARKDOWN_LINK_REG, " ").replace(PLAIN_LINK_REG, " ");
}
__name(stripIgnoredTagSegments, "stripIgnoredTagSegments");
function extractTagNamesFromMemoContent(content) {
  if (!content) {
    return [];
  }
  const sanitizedContent = stripIgnoredTagSegments(content);
  const tagMatches = [...sanitizedContent.matchAll(TAG_NAME_REG)];
  return [...new Set(tagMatches.map((match2) => match2[2]))];
}
__name(extractTagNamesFromMemoContent, "extractTagNamesFromMemoContent");
async function findTagByName(db, tagName, creatorId = null) {
  const schema = await getTagSchema(db);
  const selectColumns = buildTagSelectColumns(schema);
  if (schema.hasCreatorId && creatorId !== null && creatorId !== void 0) {
    const exactMatch = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ? AND creator_id = ?
      LIMIT 1
    `).bind(tagName, creatorId).first();
    if (exactMatch) {
      return { schema, tag: exactMatch, matchType: "owned" };
    }
    const legacyTag = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ? AND creator_id IS NULL
      LIMIT 1
    `).bind(tagName).first();
    if (legacyTag) {
      return { schema, tag: legacyTag, matchType: "legacy" };
    }
    const globalTag = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ?
      LIMIT 1
    `).bind(tagName).first();
    if (globalTag) {
      return { schema, tag: globalTag, matchType: "global" };
    }
  } else {
    const tag = await db.prepare(`
      SELECT ${selectColumns}
      FROM tags
      WHERE name = ?
      LIMIT 1
    `).bind(tagName).first();
    if (tag) {
      return { schema, tag, matchType: "global" };
    }
  }
  return { schema, tag: null, matchType: null };
}
__name(findTagByName, "findTagByName");
async function upsertTagRecord(db, rawTagName, creatorId = null) {
  const tagName = rawTagName?.trim();
  const lookup = await findTagByName(db, tagName, creatorId);
  const { schema } = lookup;
  if (lookup.tag) {
    if (lookup.matchType === "legacy" && schema.hasCreatorId && creatorId !== null && creatorId !== void 0) {
      await db.prepare(`
        UPDATE tags
        SET creator_id = ?
        WHERE id = ? AND creator_id IS NULL
      `).bind(creatorId, lookup.tag.id).run();
      const adoptedTag = await getTagById(db, lookup.tag.id, schema);
      return { tag: adoptedTag, created: false, adopted: true, schema };
    }
    return {
      tag: lookup.tag,
      created: false,
      adopted: false,
      schema,
      conflict: lookup.matchType === "global" && schema.hasCreatorId && lookup.tag.creatorId !== null && lookup.tag.creatorId !== creatorId
    };
  }
  const insertStmt = schema.hasCreatorId && creatorId !== null && creatorId !== void 0 ? db.prepare("INSERT INTO tags (name, creator_id) VALUES (?, ?)") : db.prepare("INSERT INTO tags (name) VALUES (?)");
  const bindValues = schema.hasCreatorId && creatorId !== null && creatorId !== void 0 ? [tagName, creatorId] : [tagName];
  try {
    const result = await insertStmt.bind(...bindValues).run();
    const createdTag = await getTagById(db, result.meta.last_row_id, schema);
    return { tag: createdTag, created: true, adopted: false, schema, conflict: false };
  } catch (error) {
    const conflictLookup = await findTagByName(db, tagName, creatorId);
    if (conflictLookup.tag) {
      return {
        tag: conflictLookup.tag,
        created: false,
        adopted: false,
        schema,
        conflict: conflictLookup.matchType === "global" && schema.hasCreatorId && conflictLookup.tag.creatorId !== null && conflictLookup.tag.creatorId !== creatorId
      };
    }
    throw error;
  }
}
__name(upsertTagRecord, "upsertTagRecord");
async function attachTagToMemo(db, memoId, rawTagName, creatorId = null) {
  const { tag, conflict } = await upsertTagRecord(db, rawTagName, creatorId);
  await db.prepare(`
    INSERT OR IGNORE INTO memo_tags (memo_id, tag_id)
    VALUES (?, ?)
  `).bind(memoId, tag.id).run();
  return { tag, conflict };
}
__name(attachTagToMemo, "attachTagToMemo");

// src/handlers/memos.js
var app2 = new Hono2();
app2.get("/", async (c) => {
  try {
    const db = c.env.DB;
    const limit = parseInt(c.req.query("limit")) || 20;
    const offset = parseInt(c.req.query("offset")) || 0;
    let creatorId = c.req.query("creatorId");
    const creatorUsername = c.req.query("creatorUsername");
    const rowStatus = c.req.query("rowStatus");
    const visibility = c.req.query("visibility");
    const searchText = c.req.query("text");
    const searchTag = c.req.query("tag");
    const dateFrom = c.req.query("dateFrom") ? parseInt(c.req.query("dateFrom")) : null;
    const dateTo = c.req.query("dateTo") ? parseInt(c.req.query("dateTo")) : null;
    if (creatorUsername && !creatorId) {
      const userStmt = db.prepare("SELECT id FROM users WHERE username = ?");
      const user = await userStmt.bind(creatorUsername).first();
      if (user) {
        creatorId = user.id.toString();
      }
    }
    const workerUrl = new URL(c.req.url).origin;
    const token = c.req.header("Authorization")?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    let currentUser = null;
    if (token) {
      try {
        if (token.startsWith("eyJ")) {
          const { verifyJWT: verifyJWT2, getJWTSecret: getJWTSecret2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
          const jwtSecret = getJWTSecret2(c.env);
          const payload = await verifyJWT2(token, jwtSecret);
          if (payload) {
            const userStmt = db.prepare(`
              SELECT id, username, nickname, email, avatar_url, is_admin, role
              FROM users
              WHERE id = ?
            `);
            const dbUser = await userStmt.bind(payload.id).first();
            if (dbUser) {
              currentUser = {
                id: dbUser.id,
                username: dbUser.username,
                nickname: dbUser.nickname,
                email: dbUser.email || "",
                avatarUrl: dbUser.avatar_url || "",
                isAdmin: Boolean(dbUser.is_admin) || ["host", "admin"].includes(dbUser.role),
                role: dbUser.role || (dbUser.is_admin ? "admin" : "user")
              };
            }
          }
        } else {
          const { validateSession: validateSession2 } = await Promise.resolve().then(() => (init_auth(), auth_exports));
          currentUser = await validateSession2(db, token);
        }
      } catch (e) {
        console.error("Token validation error:", e);
      }
    }
    const disablePublicMemosStmt = db.prepare("SELECT value FROM settings WHERE key = 'disable-public-memos'");
    const disablePublicMemosSetting = await disablePublicMemosStmt.first();
    const isPublicMemosDisabled = disablePublicMemosSetting?.value === "true";
    if (isPublicMemosDisabled && !currentUser) {
      return jsonResponse([]);
    }
    let whereConditions = [];
    let whereValues = [];
    let needsTagJoin = false;
    if (!rowStatus) {
      whereConditions.push("m.row_status = ?");
      whereValues.push("NORMAL");
    } else {
      whereConditions.push("m.row_status = ?");
      whereValues.push(rowStatus);
    }
    if (searchText) {
      whereConditions.push("m.content LIKE ?");
      whereValues.push(`%${searchText}%`);
    }
    if (searchTag) {
      needsTagJoin = true;
      whereConditions.push("t.name = ?");
      whereValues.push(searchTag);
    }
    if (dateFrom) {
      whereConditions.push("m.display_ts >= ?");
      whereValues.push(dateFrom);
    }
    if (dateTo) {
      whereConditions.push("m.display_ts <= ?");
      whereValues.push(dateTo);
    }
    if (creatorId) {
      if (currentUser && parseInt(creatorId) === currentUser.id) {
        whereConditions.push("m.creator_id = ?");
        whereValues.push(creatorId);
      } else {
        whereConditions.push("m.creator_id = ?");
        whereValues.push(creatorId);
        if (!visibility) {
          whereConditions.push("m.visibility = ?");
          whereValues.push("PUBLIC");
        } else {
          whereConditions.push("m.visibility = ?");
          whereValues.push(visibility);
        }
      }
    } else {
      if (currentUser) {
        if (rowStatus === "ARCHIVED") {
          whereConditions.push("m.creator_id = ?");
          whereValues.push(currentUser.id);
        } else {
          whereConditions.push("(m.creator_id = ? OR m.visibility = ?)");
          whereValues.push(currentUser.id, "PUBLIC");
        }
      } else {
        if (!visibility) {
          whereConditions.push("m.visibility = ?");
          whereValues.push("PUBLIC");
        } else {
          whereConditions.push("m.visibility = ?");
          whereValues.push(visibility);
        }
      }
    }
    const whereClause = whereConditions.length > 0 ? "WHERE " + whereConditions.join(" AND ") : "";
    const settingStmt = db.prepare(`SELECT value FROM settings WHERE key = ?`);
    const settingResult = await settingStmt.bind("memo-display-with-updated-ts").first();
    const useUpdatedTime = settingResult?.value === "true";
    const sortField = useUpdatedTime ? "m.updated_ts" : "m.display_ts";
    const tagJoinClause = needsTagJoin ? `LEFT JOIN memo_tags mt ON m.id = mt.memo_id
         LEFT JOIN tags t ON mt.tag_id = t.id` : "";
    const stmt = db.prepare(`
      SELECT ${needsTagJoin ? "DISTINCT" : ""}
        m.id,
        m.row_status as rowStatus,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.updated_ts as updatedTs,
        m.display_ts as displayTs,
        m.content,
        m.visibility,
        m.pinned,
        m.parent_id as parent,
        u.nickname as creatorName,
        u.username as creatorUsername,
        u.email as creatorEmail,
        r.id as resourceId,
        r.creator_id as resourceCreatorId,
        r.filename as resourceFilename,
        r.filepath as resourceFilepath,
        r.type as resourceType,
        r.size as resourceSize,
        r.created_ts as resourceCreatedTs
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      LEFT JOIN memo_resources mr ON m.id = mr.memo_id
      LEFT JOIN resources r ON mr.resource_id = r.id
      ${tagJoinClause}
      ${whereClause}
      ORDER BY m.pinned DESC, ${sortField} DESC
      LIMIT ? OFFSET ?
    `);
    const bindValues = [...whereValues, limit * 10, offset];
    const { results: rawResults } = await stmt.bind(...bindValues).all();
    const memosMap = /* @__PURE__ */ new Map();
    for (const row of rawResults) {
      if (!memosMap.has(row.id)) {
        memosMap.set(row.id, {
          id: row.id,
          rowStatus: row.rowStatus,
          creatorId: row.creatorId,
          createdTs: row.createdTs,
          updatedTs: row.updatedTs,
          displayTs: row.displayTs,
          content: row.content,
          visibility: row.visibility,
          pinned: Boolean(row.pinned),
          parent: row.parent,
          creatorName: row.creatorName,
          creatorUsername: row.creatorUsername,
          creatorEmail: row.creatorEmail,
          resourceList: [],
          relationList: []
        });
      }
      if (row.resourceId) {
        const memo = memosMap.get(row.id);
        memo.resourceList.push({
          id: row.resourceId,
          creatorId: row.resourceCreatorId,
          createdTs: row.resourceCreatedTs,
          updatedTs: row.resourceCreatedTs,
          filename: row.resourceFilename,
          externalLink: "",
          // 不设置 externalLink，让前端使用 getResourceUrl 生成代理URL
          type: row.resourceType,
          size: row.resourceSize
        });
      }
    }
    const results = Array.from(memosMap.values()).slice(0, limit);
    for (const memo of results) {
      const tagStmt = db.prepare(`
        SELECT t.id, t.name
        FROM tags t
        JOIN memo_tags mt ON t.id = mt.tag_id
        WHERE mt.memo_id = ?
      `);
      const { results: tags } = await tagStmt.bind(memo.id).all();
      memo.tagList = tags || [];
      const relationStmt = db.prepare(`
        SELECT
          mr.id,
          mr.memo_id as memoId,
          mr.related_memo_id as relatedMemoId,
          mr.type,
          mr.created_ts as createdTs
        FROM memo_relations mr
        WHERE mr.memo_id = ?
        ORDER BY mr.created_ts DESC
      `);
      const { results: relations } = await relationStmt.bind(memo.id).all();
      memo.relationList = relations || [];
    }
    for (const memo of results) {
      if (memo.creatorEmail) {
        const emailLower = memo.creatorEmail.toLowerCase().trim();
        memo.creatorEmailHash = simpleMD5(emailLower);
      }
      delete memo.creatorEmail;
    }
    const countStmt = db.prepare(`
      SELECT COUNT(DISTINCT m.id) as total
      FROM memos m
      ${tagJoinClause}
      ${whereClause}
    `);
    const countResult = await countStmt.bind(...whereValues).first();
    const total = countResult?.total || 0;
    return jsonResponse(results);
  } catch (error) {
    console.error("Error fetching memos:", error);
    return errorResponse("Failed to fetch memos", 500);
  }
});
app2.get("/search", async (c) => {
  try {
    const db = c.env.DB;
    const query = c.req.query("q");
    const searchContent = c.req.query("content") === "true";
    const searchTags = c.req.query("tags") === "true";
    const searchUsername = c.req.query("username") === "true";
    if (!query) {
      return errorResponse("Search query is required");
    }
    const searchPattern = `%${query}%`;
    let memoIds = /* @__PURE__ */ new Set();
    if (searchContent) {
      const contentStmt = db.prepare(`
        SELECT id FROM memos
        WHERE content LIKE ? AND row_status = 'NORMAL' AND visibility = 'PUBLIC'
      `);
      const { results } = await contentStmt.bind(searchPattern).all();
      results.forEach((r) => memoIds.add(r.id));
    }
    if (searchTags) {
      const tagStmt = db.prepare(`
        SELECT mt.memo_id
        FROM memo_tags mt
        JOIN tags t ON mt.tag_id = t.id
        JOIN memos m ON mt.memo_id = m.id
        WHERE t.name LIKE ? AND m.row_status = 'NORMAL' AND m.visibility = 'PUBLIC'
      `);
      const { results } = await tagStmt.bind(searchPattern).all();
      results.forEach((r) => memoIds.add(r.memo_id));
    }
    if (searchUsername) {
      const userStmt = db.prepare(`
        SELECT m.id
        FROM memos m
        JOIN users u ON m.creator_id = u.id
        WHERE (u.username LIKE ? OR u.nickname LIKE ?)
        AND m.row_status = 'NORMAL' AND m.visibility = 'PUBLIC'
      `);
      const { results } = await userStmt.bind(searchPattern, searchPattern).all();
      results.forEach((r) => memoIds.add(r.id));
    }
    if (memoIds.size === 0) {
      return jsonResponse([]);
    }
    const settingStmt2 = db.prepare(`SELECT value FROM settings WHERE key = ?`);
    const settingResult2 = await settingStmt2.bind("memo-display-with-updated-ts").first();
    const useUpdatedTime = settingResult2?.value === "true";
    const sortField = useUpdatedTime ? "m.updated_ts" : "m.display_ts";
    const memoIdsArray = Array.from(memoIds);
    const placeholders = memoIdsArray.map(() => "?").join(",");
    const stmt = db.prepare(`
      SELECT
        m.id,
        m.row_status as rowStatus,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.updated_ts as updatedTs,
        m.display_ts as displayTs,
        m.content,
        m.visibility,
        m.pinned,
        m.parent_id as parent,
        u.nickname as creatorName,
        u.username as creatorUsername,
        u.email as creatorEmail
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE m.id IN (${placeholders})
      ORDER BY m.pinned DESC, ${sortField} DESC
    `);
    const { results: memos } = await stmt.bind(...memoIdsArray).all();
    for (const memo of memos) {
      const resourceStmt = db.prepare(`
        SELECT r.id, r.filename, r.filepath, r.type, r.size
        FROM resources r
        JOIN memo_resources mr ON r.id = mr.resource_id
        WHERE mr.memo_id = ?
      `);
      const { results: resources } = await resourceStmt.bind(memo.id).all();
      memo.resourceList = (resources || []).map((r) => ({
        ...r,
        filepath: r.filepath.startsWith("http") || r.filepath.startsWith("/api/") ? r.filepath : `/api/v1/resource/${r.id}/file`
      }));
      const tagStmt = db.prepare(`
        SELECT t.id, t.name
        FROM tags t
        JOIN memo_tags mt ON t.id = mt.tag_id
        WHERE mt.memo_id = ?
      `);
      const { results: tags } = await tagStmt.bind(memo.id).all();
      memo.tagList = tags || [];
      if (memo.creatorEmail) {
        const emailLower = memo.creatorEmail.toLowerCase().trim();
        memo.creatorEmailHash = simpleMD5(emailLower);
      }
      delete memo.creatorEmail;
      memo.pinned = Boolean(memo.pinned);
    }
    return jsonResponse(memos);
  } catch (error) {
    console.error("Error searching memos:", error);
    return errorResponse("Failed to search memos", 500);
  }
});
app2.get("/stats", async (c) => {
  try {
    const db = c.env.DB;
    const creatorId = c.req.query("creatorId");
    const creatorUsername = c.req.query("creatorUsername");
    if (!creatorId && !creatorUsername) {
      return errorResponse("creatorId or creatorUsername parameter is required", 400);
    }
    let userId = creatorId;
    if (creatorUsername && !creatorId) {
      const userStmt = db.prepare("SELECT id FROM users WHERE username = ?");
      const user = await userStmt.bind(creatorUsername).first();
      if (!user) {
        return errorResponse("User not found", 404);
      }
      userId = user.id;
    } else if (creatorId) {
      const userStmt = db.prepare("SELECT id FROM users WHERE id = ?");
      const user = await userStmt.bind(creatorId).first();
      if (!user) {
        return errorResponse("User not found", 404);
      }
    }
    const stmt = db.prepare(`
      SELECT created_ts as createdTs
      FROM memos
      WHERE creator_id = ? AND row_status = 'NORMAL'
      ORDER BY created_ts DESC
    `);
    const { results } = await stmt.bind(userId).all();
    const timestamps = results.map((memo) => memo.createdTs);
    return jsonResponse(timestamps);
  } catch (error) {
    console.error("Error fetching memo stats:", error);
    return errorResponse("Failed to fetch memo stats", 500);
  }
});
app2.get("/all", async (c) => {
  try {
    const db = c.env.DB;
    const limit = parseInt(c.req.query("limit")) || 20;
    const offset = parseInt(c.req.query("offset")) || 0;
    const creatorUsername = c.req.query("creatorUsername");
    const workerUrl = new URL(c.req.url).origin;
    const token = c.req.header("Authorization")?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    let currentUser = null;
    if (token) {
      try {
        if (token.startsWith("eyJ")) {
          const { verifyJWT: verifyJWT2, getJWTSecret: getJWTSecret2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
          const jwtSecret = getJWTSecret2(c.env);
          const payload = await verifyJWT2(token, jwtSecret);
          if (payload) {
            const userStmt = db.prepare(`
              SELECT id, username, nickname, email, avatar_url, is_admin, role
              FROM users
              WHERE id = ?
            `);
            const dbUser = await userStmt.bind(payload.id).first();
            if (dbUser) {
              currentUser = {
                id: dbUser.id,
                username: dbUser.username,
                nickname: dbUser.nickname,
                email: dbUser.email || "",
                avatarUrl: dbUser.avatar_url || "",
                isAdmin: Boolean(dbUser.is_admin) || ["host", "admin"].includes(dbUser.role),
                role: dbUser.role || (dbUser.is_admin ? "admin" : "user")
              };
            }
          }
        } else {
          const { validateSession: validateSession2 } = await Promise.resolve().then(() => (init_auth(), auth_exports));
          currentUser = await validateSession2(c.env.DB, token);
        }
      } catch (e) {
        console.error("Token validation error:", e);
      }
    }
    const disablePublicMemosStmt = db.prepare("SELECT value FROM settings WHERE key = 'disable-public-memos'");
    const disablePublicMemosSetting = await disablePublicMemosStmt.first();
    const isPublicMemosDisabled = disablePublicMemosSetting?.value === "true";
    if (isPublicMemosDisabled && !currentUser) {
      return jsonResponse([]);
    }
    let whereConditions = ["m.row_status = ?", "m.visibility != ?"];
    let whereValues = ["NORMAL", "PRIVATE"];
    if (creatorUsername) {
      whereConditions.push("u.username = ?");
      whereValues.push(creatorUsername);
    }
    const whereClause = whereConditions.join(" AND ");
    const settingStmt = db.prepare(`SELECT value FROM settings WHERE key = ?`);
    const settingResult = await settingStmt.bind("memo-display-with-updated-ts").first();
    const useUpdatedTime = settingResult?.value === "true";
    const sortField = useUpdatedTime ? "m.updated_ts" : "m.created_ts";
    const stmt = db.prepare(`
      SELECT
        m.id,
        m.creator_id,
        m.content,
        m.visibility,
        m.pinned,
        m.created_ts,
        m.updated_ts,
        m.row_status,
        u.id as user_id,
        u.username,
        u.nickname,
        u.email,
        r.id as resourceId,
        r.creator_id as resourceCreatorId,
        r.filename as resourceFilename,
        r.filepath as resourceFilepath,
        r.type as resourceType,
        r.size as resourceSize,
        r.created_ts as resourceCreatedTs
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      LEFT JOIN memo_resources mr ON m.id = mr.memo_id
      LEFT JOIN resources r ON mr.resource_id = r.id
      WHERE ${whereClause}
      ORDER BY ${sortField} DESC
      LIMIT ? OFFSET ?
    `);
    const { results: rawResults } = await stmt.bind(...whereValues, limit * 10, offset).all();
    const memosMap = /* @__PURE__ */ new Map();
    for (const row of rawResults) {
      if (!memosMap.has(row.id)) {
        const emailHash = simpleMD5((row.email || "").toLowerCase().trim());
        const gravatarUrl = `https://gravatar.loli.net/avatar/${emailHash}?d=mp`;
        memosMap.set(row.id, {
          id: row.id,
          creatorId: row.creator_id,
          createdTs: row.created_ts,
          updatedTs: row.updated_ts,
          displayTs: row.created_ts,
          content: row.content,
          visibility: row.visibility,
          pinned: Boolean(row.pinned),
          rowStatus: row.row_status,
          creatorUsername: row.username,
          creatorName: row.nickname || row.username,
          resourceList: [],
          relationList: [],
          creator: {
            id: row.user_id,
            username: row.username,
            nickname: row.nickname,
            email: row.email || "",
            avatarUrl: gravatarUrl
          }
        });
      }
      if (row.resourceId) {
        const memo = memosMap.get(row.id);
        memo.resourceList.push({
          id: row.resourceId,
          creatorId: row.resourceCreatorId,
          createdTs: row.resourceCreatedTs,
          updatedTs: row.resourceCreatedTs,
          filename: row.resourceFilename,
          externalLink: "",
          // 不设置 externalLink，让前端使用 getResourceUrl 生成代理URL
          type: row.resourceType,
          size: row.resourceSize
        });
      }
    }
    const memos = Array.from(memosMap.values()).slice(0, limit);
    return c.json(memos);
  } catch (error) {
    console.error("Error fetching all memos:", error);
    return errorResponse("Failed to fetch memos", 500);
  }
});
app2.get("/:id", async (c) => {
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const stmt = db.prepare(`
      SELECT
        m.id,
        m.row_status as rowStatus,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.updated_ts as updatedTs,
        m.display_ts as displayTs,
        m.content,
        m.visibility,
        m.pinned,
        m.parent_id as parent,
        u.nickname as creatorName,
        u.username as creatorUsername,
        u.email as creatorEmail,
        r.id as resourceId,
        r.creator_id as resourceCreatorId,
        r.filename as resourceFilename,
        r.filepath as resourceFilepath,
        r.type as resourceType,
        r.size as resourceSize,
        r.created_ts as resourceCreatedTs
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      LEFT JOIN memo_resources mr ON m.id = mr.memo_id
      LEFT JOIN resources r ON mr.resource_id = r.id
      WHERE m.id = ? AND m.row_status = 'NORMAL'
    `);
    const { results: rawResults } = await stmt.bind(id).all();
    if (!rawResults || rawResults.length === 0) {
      return errorResponse("Memo not found", 404);
    }
    const firstRow = rawResults[0];
    const token = c.req.header("Authorization")?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    let currentUser = null;
    if (token) {
      try {
        if (token.startsWith("eyJ")) {
          const { verifyJWT: verifyJWT2, getJWTSecret: getJWTSecret2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
          const jwtSecret = getJWTSecret2(c.env);
          const payload = await verifyJWT2(token, jwtSecret);
          if (payload) {
            const userStmt = db.prepare(`
              SELECT id, username, nickname, email, avatar_url, is_admin, role
              FROM users
              WHERE id = ?
            `);
            const dbUser = await userStmt.bind(payload.id).first();
            if (dbUser) {
              currentUser = {
                id: dbUser.id,
                username: dbUser.username,
                nickname: dbUser.nickname,
                email: dbUser.email || "",
                avatarUrl: dbUser.avatar_url || "",
                isAdmin: Boolean(dbUser.is_admin) || ["host", "admin"].includes(dbUser.role),
                role: dbUser.role || (dbUser.is_admin ? "admin" : "user")
              };
            }
          }
        } else {
          const { validateSession: validateSession2 } = await Promise.resolve().then(() => (init_auth(), auth_exports));
          currentUser = await validateSession2(c.env.DB, token);
        }
      } catch (e) {
        console.error("Token validation error:", e);
      }
    }
    const disablePublicMemosStmt = db.prepare("SELECT value FROM settings WHERE key = 'disable-public-memos'");
    const disablePublicMemosSetting = await disablePublicMemosStmt.first();
    const isPublicMemosDisabled = disablePublicMemosSetting?.value === "true";
    if (isPublicMemosDisabled && !currentUser) {
      return errorResponse("Access denied. Please login to view memos.", 403);
    }
    if (firstRow.visibility === "PRIVATE" && (!currentUser || currentUser.id !== firstRow.creatorId)) {
      return errorResponse("Access denied. This memo is private.", 403);
    }
    const memo = {
      id: firstRow.id,
      rowStatus: firstRow.rowStatus,
      creatorId: firstRow.creatorId,
      createdTs: firstRow.createdTs,
      updatedTs: firstRow.updatedTs,
      displayTs: firstRow.displayTs,
      content: firstRow.content,
      visibility: firstRow.visibility,
      pinned: Boolean(firstRow.pinned),
      parent: firstRow.parent,
      creatorName: firstRow.creatorName,
      creatorUsername: firstRow.creatorUsername,
      creatorEmail: firstRow.creatorEmail,
      resourceList: [],
      relationList: []
    };
    for (const row of rawResults) {
      if (row.resourceId) {
        memo.resourceList.push({
          id: row.resourceId,
          creatorId: row.resourceCreatorId,
          createdTs: row.resourceCreatedTs,
          updatedTs: row.resourceCreatedTs,
          filename: row.resourceFilename,
          externalLink: "",
          // 不设置 externalLink，让前端使用 getResourceUrl 生成代理URL
          type: row.resourceType,
          size: row.resourceSize
        });
      }
    }
    const tagStmt = db.prepare(`
      SELECT t.id, t.name
      FROM tags t
      JOIN memo_tags mt ON t.id = mt.tag_id
      WHERE mt.memo_id = ?
    `);
    const { results: tags } = await tagStmt.bind(id).all();
    memo.tagList = tags || [];
    const relationStmt = db.prepare(`
      SELECT
        mr.id,
        mr.memo_id as memoId,
        mr.related_memo_id as relatedMemoId,
        mr.type,
        mr.created_ts as createdTs
      FROM memo_relations mr
      WHERE mr.memo_id = ?
      ORDER BY mr.created_ts DESC
    `);
    const { results: relations } = await relationStmt.bind(id).all();
    memo.relationList = relations || [];
    delete memo.creatorEmail;
    return jsonResponse(memo);
  } catch (error) {
    console.error("Error fetching memo:", error);
    return errorResponse("Failed to fetch memo", 500);
  }
});
app2.post("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const workerUrl = new URL(c.req.url).origin;
    if (!body.content && (!body.resourceIdList || body.resourceIdList.length === 0)) {
      return errorResponse("Content or resources are required");
    }
    let creatorId = c.get("user")?.id;
    if (!creatorId) {
      const userCheck = await db.prepare("SELECT COUNT(*) as count FROM users").first();
      if (userCheck.count === 0) {
        const randomPassword = generateSecurePassword(16);
        const passwordHash = await hashPassword(randomPassword);
        const userStmt2 = db.prepare(`
          INSERT INTO users (username, nickname, password_hash, is_admin)
          VALUES (?, ?, ?, 1)
        `);
        const userResult = await userStmt2.bind("admin", "\u7BA1\u7406\u5458", passwordHash).run();
        creatorId = userResult.meta.last_row_id;
        console.log("=".repeat(60));
        console.log("\u26A0\uFE0F  IMPORTANT: Default admin user created");
        console.log("Username: admin");
        console.log(`Password: ${randomPassword}`);
        console.log("Please change this password immediately after first login!");
        console.log("=".repeat(60));
      } else {
        creatorId = 1;
      }
    }
    const tagNames = extractTagNamesFromMemoContent(body.content);
    const stmt = db.prepare(`
      INSERT INTO memos (creator_id, content, visibility, display_ts)
      VALUES (?, ?, ?, ?)
    `);
    const now = Math.floor(Date.now() / 1e3);
    const result = await stmt.bind(
      creatorId,
      body.content || "",
      // 保留原始内容，包括 tag
      body.visibility || "PUBLIC",
      now
    ).run();
    const memoId = result.meta.last_row_id;
    for (const tagName of tagNames) {
      await attachTagToMemo(db, memoId, tagName, creatorId);
    }
    if (body.resourceIdList && Array.isArray(body.resourceIdList)) {
      for (const resourceId of body.resourceIdList) {
        const linkStmt = db.prepare(`
          INSERT INTO memo_resources (memo_id, resource_id)
          VALUES (?, ?)
        `);
        await linkStmt.bind(memoId, resourceId).run();
      }
    }
    const userStmt = db.prepare("SELECT id, username, nickname FROM users WHERE id = ?");
    const creator = await userStmt.bind(creatorId).first();
    const notificationData = {
      id: memoId,
      content: body.content || "",
      visibility: body.visibility || "PUBLIC",
      creatorId,
      creatorUsername: creator?.username || "unknown",
      creatorName: creator?.nickname || creator?.username || "unknown",
      createdTs: now,
      tags: tagNames,
      resourceCount: body.resourceIdList?.length || 0
    };
    console.log("\u{1F4DD} Memo created, preparing to send notifications:", {
      memoId,
      visibility: notificationData.visibility,
      creatorId: notificationData.creatorId,
      creatorUsername: notificationData.creatorUsername
    });
    c.executionCtx.waitUntil(
      sendAllNotifications(db, notificationData).catch((err) => {
        console.error("\u274C Notification error in waitUntil:", err);
      })
    );
    const memoStmt = db.prepare(`
      SELECT
        m.id,
        m.row_status as rowStatus,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.updated_ts as updatedTs,
        m.display_ts as displayTs,
        m.content,
        m.visibility,
        m.pinned,
        m.parent_id as parent,
        u.nickname as creatorName,
        u.username as creatorUsername,
        u.email as creatorEmail
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE m.id = ?
    `);
    const createdMemo = await memoStmt.bind(memoId).first();
    if (!createdMemo) {
      return errorResponse("Failed to retrieve created memo", 500);
    }
    const resourcesStmt = db.prepare(`
      SELECT r.id, r.filename, r.filepath, r.type, r.size, r.created_ts
      FROM resources r
      INNER JOIN memo_resources mr ON r.id = mr.resource_id
      WHERE mr.memo_id = ?
    `);
    const { results: resources } = await resourcesStmt.bind(memoId).all();
    const tagsStmt = db.prepare(`
      SELECT t.name
      FROM tags t
      INNER JOIN memo_tags mt ON t.id = mt.tag_id
      WHERE mt.memo_id = ?
    `);
    const { results: tags } = await tagsStmt.bind(memoId).all();
    const fullMemo = {
      id: createdMemo.id,
      rowStatus: createdMemo.rowStatus || "NORMAL",
      creatorId: createdMemo.creatorId,
      createdTs: createdMemo.createdTs,
      updatedTs: createdMemo.updatedTs,
      displayTs: createdMemo.displayTs,
      content: createdMemo.content,
      visibility: createdMemo.visibility,
      pinned: Boolean(createdMemo.pinned),
      parent: createdMemo.parent,
      creatorName: createdMemo.creatorName,
      creatorUsername: createdMemo.creatorUsername,
      resourceList: resources.map((r) => ({
        id: r.id,
        filename: r.filename,
        externalLink: r.filepath.startsWith("http") ? r.filepath : `${workerUrl}/o/r/${r.id}/${r.filename}`,
        type: r.type,
        size: r.size,
        createdTs: r.created_ts
      })),
      relationList: [],
      tagList: tags.map((t) => t.name)
    };
    return jsonResponse(fullMemo, 201);
  } catch (error) {
    console.error("Error creating memo:", error);
    return errorResponse("Failed to create memo", 500);
  }
});
app2.patch("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    if (!body.content && !body.rowStatus && body.visibility === void 0 && body.pinned === void 0) {
      return errorResponse("At least one field is required for update", 400);
    }
    const memoStmt = db.prepare(`
      SELECT creator_id
      FROM memos
      WHERE id = ?
    `);
    const memo = await memoStmt.bind(id).first();
    if (!memo) {
      return errorResponse("Memo not found", 404);
    }
    const currentUser = c.get("user");
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    if (memo.creator_id !== currentUser.id && !currentUser.isAdmin) {
      return errorResponse("Permission denied: You can only edit your own memos", 403);
    }
    const updateFields = ["updated_ts = ?"];
    const updateValues = [Math.floor(Date.now() / 1e3)];
    if (body.content !== void 0) {
      updateFields.push("content = ?");
      updateValues.push(body.content);
    }
    if (body.rowStatus !== void 0) {
      updateFields.push("row_status = ?");
      updateValues.push(body.rowStatus);
    }
    if (body.visibility !== void 0) {
      updateFields.push("visibility = ?");
      updateValues.push(body.visibility);
    }
    if (body.pinned !== void 0) {
      updateFields.push("pinned = ?");
      updateValues.push(body.pinned ? 1 : 0);
    }
    const updateStmt = db.prepare(`
      UPDATE memos
      SET ${updateFields.join(", ")}
      WHERE id = ?
    `);
    updateValues.push(id);
    const result = await updateStmt.bind(...updateValues).run();
    if (result.changes === 0) {
      return errorResponse("Failed to update memo", 500);
    }
    if (body.content !== void 0) {
      await db.prepare(`
        DELETE FROM memo_tags
        WHERE memo_id = ?
      `).bind(id).run();
      const tagNames = extractTagNamesFromMemoContent(body.content);
      for (const tagName of tagNames) {
        await attachTagToMemo(db, id, tagName, memo.creator_id);
      }
    }
    if (body.deleteResourceIds && Array.isArray(body.deleteResourceIds)) {
      for (const resourceId of body.deleteResourceIds) {
        const deleteStmt = db.prepare(`
          DELETE FROM memo_resources
          WHERE memo_id = ? AND resource_id = ?
        `);
        await deleteStmt.bind(id, resourceId).run();
      }
    }
    if (body.resourceIdList && Array.isArray(body.resourceIdList)) {
      for (const resourceId of body.resourceIdList) {
        const checkStmt = db.prepare(`
          SELECT COUNT(*) as count
          FROM memo_resources
          WHERE memo_id = ? AND resource_id = ?
        `);
        const existing = await checkStmt.bind(id, resourceId).first();
        if (existing.count === 0) {
          const linkStmt = db.prepare(`
            INSERT INTO memo_resources (memo_id, resource_id)
            VALUES (?, ?)`);
          await linkStmt.bind(id, resourceId).run();
        }
      }
    }
    const getMemoStmt = db.prepare(`
      SELECT
        m.id,
        m.row_status as rowStatus,
        m.creator_id as creatorId,
        m.created_ts as createdTs,
        m.updated_ts as updatedTs,
        m.display_ts as displayTs,
        m.content,
        m.visibility,
        m.pinned,
        m.parent_id as parent,
        u.nickname as creatorName,
        u.username as creatorUsername
      FROM memos m
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE m.id = ?
    `);
    const updatedMemo = await getMemoStmt.bind(id).first();
    const resourceStmt = db.prepare(`
      SELECT r.id, r.filename, r.type, r.size, r.created_ts as createdTs
      FROM resources r
      JOIN memo_resources mr ON r.id = mr.resource_id
      WHERE mr.memo_id = ?
    `);
    const { results: resources } = await resourceStmt.bind(id).all();
    const tagStmt = db.prepare(`
      SELECT t.id, t.name
      FROM tags t
      JOIN memo_tags mt ON t.id = mt.tag_id
      WHERE mt.memo_id = ?
    `);
    const { results: tags } = await tagStmt.bind(id).all();
    const fullMemo = {
      id: updatedMemo.id,
      rowStatus: updatedMemo.rowStatus,
      creatorId: updatedMemo.creatorId,
      createdTs: updatedMemo.createdTs,
      updatedTs: updatedMemo.updatedTs,
      displayTs: updatedMemo.displayTs,
      content: updatedMemo.content,
      visibility: updatedMemo.visibility,
      pinned: Boolean(updatedMemo.pinned),
      parent: updatedMemo.parent,
      creatorName: updatedMemo.creatorName,
      creatorUsername: updatedMemo.creatorUsername,
      resourceList: resources.map((r) => ({
        id: r.id,
        filename: r.filename,
        type: r.type,
        size: r.size,
        createdTs: r.createdTs,
        updatedTs: r.createdTs,
        externalLink: ""
      })),
      tagList: tags || [],
      relationList: []
    };
    return jsonResponse(fullMemo);
  } catch (error) {
    console.error("Error updating memo:", error);
    return errorResponse("Failed to update memo", 500);
  }
});
app2.put("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    if (!body.content) {
      return errorResponse("Content is required");
    }
    const memoStmt = db.prepare(`
      SELECT creator_id
      FROM memos
      WHERE id = ? AND row_status = 'NORMAL'
    `);
    const memo = await memoStmt.bind(id).first();
    if (!memo) {
      return errorResponse("Memo not found", 404);
    }
    const currentUser = c.get("user");
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    if (memo.creator_id !== currentUser.id && !currentUser.isAdmin) {
      return errorResponse("Permission denied: You can only edit your own memos", 403);
    }
    const updateFields = ["content = ?", "updated_ts = ?"];
    const updateValues = [body.content, Math.floor(Date.now() / 1e3)];
    if (body.visibility !== void 0) {
      updateFields.push("visibility = ?");
      updateValues.push(body.visibility);
    }
    if (body.pinned !== void 0) {
      updateFields.push("pinned = ?");
      updateValues.push(body.pinned ? 1 : 0);
    }
    const updateStmt = db.prepare(`
      UPDATE memos
      SET ${updateFields.join(", ")}
      WHERE id = ? AND row_status = 'NORMAL'
    `);
    updateValues.push(id);
    const result = await updateStmt.bind(...updateValues).run();
    if (result.changes === 0) {
      return errorResponse("Failed to update memo", 500);
    }
    await db.prepare(`
      DELETE FROM memo_tags
      WHERE memo_id = ?
    `).bind(id).run();
    const tagNames = extractTagNamesFromMemoContent(body.content);
    for (const tagName of tagNames) {
      await attachTagToMemo(db, id, tagName, memo.creator_id);
    }
    if (body.deleteResourceIds && Array.isArray(body.deleteResourceIds)) {
      for (const resourceId of body.deleteResourceIds) {
        const deleteStmt = db.prepare(`
          DELETE FROM memo_resources
          WHERE memo_id = ? AND resource_id = ?
        `);
        await deleteStmt.bind(id, resourceId).run();
      }
    }
    if (body.resourceIdList && Array.isArray(body.resourceIdList)) {
      for (const resourceId of body.resourceIdList) {
        const checkStmt = db.prepare(`
          SELECT COUNT(*) as count
          FROM memo_resources
          WHERE memo_id = ? AND resource_id = ?
        `);
        const existing = await checkStmt.bind(id, resourceId).first();
        if (existing.count === 0) {
          const linkStmt = db.prepare(`
            INSERT INTO memo_resources (memo_id, resource_id)
            VALUES (?, ?)
          `);
          await linkStmt.bind(id, resourceId).run();
        }
      }
    }
    return jsonResponse({ message: "Memo updated successfully" });
  } catch (error) {
    console.error("Error updating memo:", error);
    return errorResponse("Failed to update memo", 500);
  }
});
app2.delete("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const memoStmt = db.prepare(`
      SELECT creator_id, row_status
      FROM memos
      WHERE id = ?
    `);
    const memo = await memoStmt.bind(id).first();
    if (!memo) {
      return errorResponse("Memo not found", 404);
    }
    const currentUser = c.get("user");
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    if (memo.creator_id !== currentUser.id && !currentUser.isAdmin) {
      return errorResponse("Permission denied: You can only delete your own memos", 403);
    }
    const now = Math.floor(Date.now() / 1e3);
    let result;
    if (memo.row_status === "ARCHIVED") {
      const deleteStmt = db.prepare(`DELETE FROM memos WHERE id = ?`);
      result = await deleteStmt.bind(id).run();
    } else {
      const archiveStmt = db.prepare(`
        UPDATE memos
        SET row_status = 'ARCHIVED', updated_ts = ?
        WHERE id = ?
      `);
      result = await archiveStmt.bind(now, id).run();
    }
    if (result.changes === 0) {
      return errorResponse("Failed to delete memo", 500);
    }
    return jsonResponse({
      message: memo.row_status === "ARCHIVED" ? "Memo permanently deleted" : "Memo archived successfully"
    });
  } catch (error) {
    console.error("Error deleting memo:", error);
    return errorResponse("Failed to delete memo", 500);
  }
});
app2.get("/stats/heatmap", async (c) => {
  try {
    const db = c.env.DB;
    const now = Math.floor(Date.now() / 1e3);
    const thirtyDaysAgo = now - 30 * 24 * 60 * 60;
    const stmt = db.prepare(`
      SELECT
        DATE(created_ts, 'unixepoch') as date,
        COUNT(*) as count
      FROM memos
      WHERE row_status = 'NORMAL'
        AND visibility = 'PUBLIC'
        AND created_ts >= ?
      GROUP BY DATE(created_ts, 'unixepoch')
      ORDER BY date ASC
    `);
    const { results } = await stmt.bind(thirtyDaysAgo).all();
    const heatmapData = {};
    results.forEach((row) => {
      heatmapData[row.date] = row.count;
    });
    return jsonResponse(heatmapData);
  } catch (error) {
    console.error("Error fetching heatmap data:", error);
    return errorResponse("Failed to fetch heatmap data", 500);
  }
});
app2.post("/:id/organizer", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    if (body.pinned === void 0) {
      return errorResponse("pinned field is required", 400);
    }
    const memoStmt = db.prepare(`
      SELECT creator_id
      FROM memos
      WHERE id = ? AND row_status = 'NORMAL'
    `);
    const memo = await memoStmt.bind(id).first();
    if (!memo) {
      return errorResponse("Memo not found", 404);
    }
    const currentUser = c.get("user");
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    if (memo.creator_id !== currentUser.id && !["host", "admin"].includes(currentUser.role)) {
      return errorResponse("Permission denied: You can only organize your own memos", 403);
    }
    const updateStmt = db.prepare(`
      UPDATE memos
      SET pinned = ?, updated_ts = ?
      WHERE id = ? AND row_status = 'NORMAL'
    `);
    const now = Math.floor(Date.now() / 1e3);
    const result = await updateStmt.bind(body.pinned ? 1 : 0, now, id).run();
    if (result.changes === 0) {
      return errorResponse("Failed to update memo organizer", 500);
    }
    return jsonResponse({
      id: parseInt(id),
      pinned: Boolean(body.pinned),
      message: body.pinned ? "Memo pinned successfully" : "Memo unpinned successfully"
    });
  } catch (error) {
    console.error("Error updating memo organizer:", error);
    return errorResponse("Failed to update memo organizer", 500);
  }
});
var memos_default = app2;

// src/handlers/memoRelations.js
init_auth();
var app3 = new Hono2();
app3.get("/:id/relation", async (c) => {
  try {
    const db = c.env.DB;
    const memoId = c.req.param("id");
    const memoStmt = db.prepare("SELECT id FROM memos WHERE id = ? AND row_status = ?");
    const memo = await memoStmt.bind(memoId, "NORMAL").first();
    if (!memo) {
      return errorResponse("Memo not found", 404);
    }
    const stmt = db.prepare(`
      SELECT
        mr.id,
        mr.memo_id as memoId,
        mr.related_memo_id as relatedMemoId,
        mr.type,
        mr.created_ts as createdTs,
        m.content as relatedMemoContent,
        m.creator_id as relatedMemoCreatorId,
        u.username as relatedMemoCreatorUsername,
        u.nickname as relatedMemoCreatorName
      FROM memo_relations mr
      LEFT JOIN memos m ON mr.related_memo_id = m.id
      LEFT JOIN users u ON m.creator_id = u.id
      WHERE mr.memo_id = ?
      ORDER BY mr.created_ts DESC
    `);
    const { results } = await stmt.bind(memoId).all();
    return jsonResponse(results || []);
  } catch (error) {
    console.error("Error fetching memo relations:", error);
    return errorResponse("Failed to fetch memo relations", 500);
  }
});
app3.post("/:id/relation", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const memoId = c.req.param("id");
    const body = await c.req.json();
    if (!body.relatedMemoId) {
      return errorResponse("relatedMemoId is required", 400);
    }
    if (!body.type || !["REFERENCE", "COMMENT"].includes(body.type)) {
      return errorResponse("type must be either REFERENCE or COMMENT", 400);
    }
    const checkStmt = db.prepare(`
      SELECT id FROM memos WHERE id IN (?, ?) AND row_status = 'NORMAL'
    `);
    const { results: memos } = await checkStmt.bind(memoId, body.relatedMemoId).all();
    if (memos.length !== 2) {
      return errorResponse("One or both memos not found", 404);
    }
    if (parseInt(memoId) === parseInt(body.relatedMemoId)) {
      return errorResponse("Cannot create relation to self", 400);
    }
    const existingStmt = db.prepare(`
      SELECT id FROM memo_relations
      WHERE memo_id = ? AND related_memo_id = ? AND type = ?
    `);
    const existing = await existingStmt.bind(memoId, body.relatedMemoId, body.type).first();
    if (existing) {
      return errorResponse("Relation already exists", 409);
    }
    const insertStmt = db.prepare(`
      INSERT INTO memo_relations (memo_id, related_memo_id, type)
      VALUES (?, ?, ?)
    `);
    const result = await insertStmt.bind(memoId, body.relatedMemoId, body.type).run();
    return jsonResponse({
      id: result.meta.last_row_id,
      memoId: parseInt(memoId),
      relatedMemoId: body.relatedMemoId,
      type: body.type,
      message: "Relation created successfully"
    }, 201);
  } catch (error) {
    console.error("Error creating memo relation:", error);
    return errorResponse("Failed to create memo relation", 500);
  }
});
app3.delete("/:id/relation/:relatedId/type/:type", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const memoId = c.req.param("id");
    const relatedId = c.req.param("relatedId");
    const type = c.req.param("type");
    if (!["REFERENCE", "COMMENT"].includes(type)) {
      return errorResponse("type must be either REFERENCE or COMMENT", 400);
    }
    const checkStmt = db.prepare(`
      SELECT id FROM memo_relations
      WHERE memo_id = ? AND related_memo_id = ? AND type = ?
    `);
    const relation = await checkStmt.bind(memoId, relatedId, type).first();
    if (!relation) {
      return errorResponse("Relation not found", 404);
    }
    const deleteStmt = db.prepare(`
      DELETE FROM memo_relations
      WHERE memo_id = ? AND related_memo_id = ? AND type = ?
    `);
    const result = await deleteStmt.bind(memoId, relatedId, type).run();
    if (result.changes === 0) {
      return errorResponse("Failed to delete relation", 500);
    }
    return jsonResponse({
      message: "Relation deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting memo relation:", error);
    return errorResponse("Failed to delete memo relation", 500);
  }
});
var memoRelations_default = app3;

// src/handlers/tags.js
init_auth();
var app4 = new Hono2();
app4.get("/", async (c) => {
  const token = c.req.header("Authorization")?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
  let currentUser = null;
  if (token) {
    try {
      if (token.startsWith("eyJ")) {
        const { verifyJWT: verifyJWT2, getJWTSecret: getJWTSecret2 } = await Promise.resolve().then(() => (init_jwt(), jwt_exports));
        const jwtSecret = getJWTSecret2(c.env);
        const payload = await verifyJWT2(token, jwtSecret);
        if (payload) {
          currentUser = { id: payload.id };
        }
      } else {
        const { validateSession: validateSession2 } = await Promise.resolve().then(() => (init_auth(), auth_exports));
        const sessionUser = await validateSession2(c.env.DB, token);
        if (sessionUser) {
          currentUser = { id: sessionUser.id };
        }
      }
    } catch (e) {
    }
  }
  try {
    const db = c.env.DB;
    const tagSchema = await getTagSchema(db);
    const userIdParam = c.req.query("userId");
    let targetUserId = null;
    if (userIdParam) {
      const isNumeric = /^\d+$/.test(userIdParam);
      if (isNumeric) {
        targetUserId = parseInt(userIdParam);
      } else {
        const userStmt = db.prepare("SELECT id FROM users WHERE username = ?");
        const user = await userStmt.bind(userIdParam).first();
        if (user) {
          targetUserId = user.id;
        }
      }
    } else if (currentUser) {
      targetUserId = currentUser.id;
    }
    if (!targetUserId) {
      return jsonResponse([]);
    }
    const selectColumns = [
      "t.id",
      "t.name",
      tagSchema.hasCreatorId ? "t.creator_id as creatorId" : "NULL as creatorId",
      tagSchema.hasCreatedTs ? "t.created_ts as createdTs" : "NULL as createdTs",
      "COUNT(DISTINCT mt.memo_id) as memoCount"
    ];
    const groupByColumns = ["t.id", "t.name"];
    if (tagSchema.hasCreatorId) {
      groupByColumns.push("t.creator_id");
    }
    if (tagSchema.hasCreatedTs) {
      groupByColumns.push("t.created_ts");
    }
    let query = `
      SELECT
        ${selectColumns.join(",\n        ")}
      FROM tags t
      LEFT JOIN memo_tags mt ON t.id = mt.tag_id
      LEFT JOIN memos m ON mt.memo_id = m.id AND m.row_status = 'NORMAL'
    `;
    const whereConditions = [];
    const bindValues = [];
    if (tagSchema.hasCreatorId) {
      whereConditions.push("(t.creator_id = ? OR t.creator_id IS NULL)");
      bindValues.push(targetUserId);
    }
    if (whereConditions.length > 0) {
      query += " WHERE " + whereConditions.join(" AND ");
    }
    query += `
      GROUP BY ${groupByColumns.join(", ")}
      ORDER BY memoCount DESC, t.name ASC
    `;
    const stmt = db.prepare(query);
    const { results } = await stmt.bind(...bindValues).all();
    return jsonResponse(results || []);
  } catch (error) {
    console.error("Error fetching tags:", error);
    return errorResponse("Failed to fetch tags", 500);
  }
});
app4.post("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const currentUser = c.get("user");
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    if (!body.name || !body.name.trim()) {
      return errorResponse("Tag name is required", 400);
    }
    const tagName = body.name.trim();
    const { tag, created, conflict } = await upsertTagRecord(db, tagName, currentUser.id);
    if (conflict) {
      return errorResponse("Tag name already exists", 409);
    }
    return jsonResponse({
      ...tag,
      message: created ? "Tag created successfully" : "Tag already exists"
    }, created ? 201 : 200);
  } catch (error) {
    console.error("Error creating tag:", error);
    return errorResponse("Failed to create tag", 500);
  }
});
app4.get("/suggestion", async (c) => {
  try {
    const db = c.env.DB;
    const limit = parseInt(c.req.query("limit")) || 10;
    const stmt = db.prepare(`
      SELECT
        t.id,
        t.name,
        COUNT(DISTINCT mt.memo_id) as memoCount
      FROM tags t
      JOIN memo_tags mt ON t.id = mt.tag_id
      JOIN memos m ON mt.memo_id = m.id
      WHERE m.row_status = 'NORMAL'
      GROUP BY t.id, t.name
      ORDER BY memoCount DESC, t.name ASC
      LIMIT ?
    `);
    const { results } = await stmt.bind(limit).all();
    return jsonResponse(results || []);
  } catch (error) {
    console.error("Error fetching tag suggestions:", error);
    return errorResponse("Failed to fetch tag suggestions", 500);
  }
});
app4.post("/delete", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const currentUser = c.get("user");
    const tagSchema = await getTagSchema(db);
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    if (!body.name) {
      return errorResponse("Tag name is required", 400);
    }
    const selectColumns = tagSchema.hasCreatorId ? "id, creator_id" : "id, NULL as creator_id";
    const checkStmt = db.prepare(`SELECT ${selectColumns} FROM tags WHERE name = ?`);
    const tag = await checkStmt.bind(body.name).first();
    if (!tag) {
      return errorResponse("Tag not found", 404);
    }
    if (tagSchema.hasCreatorId && tag.creator_id !== null && tag.creator_id !== currentUser.id) {
      return errorResponse("Permission denied: You can only delete tags you created", 403);
    }
    const deleteStmt = db.prepare("DELETE FROM tags WHERE id = ?");
    const result = await deleteStmt.bind(tag.id).run();
    if (result.changes === 0) {
      return errorResponse("Failed to delete tag", 500);
    }
    return jsonResponse({
      message: "Tag deleted successfully",
      name: body.name
    });
  } catch (error) {
    console.error("Error deleting tag:", error);
    return errorResponse("Failed to delete tag", 500);
  }
});
app4.delete("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const tagId = c.req.param("id");
    const currentUser = c.get("user");
    const tagSchema = await getTagSchema(db);
    if (!currentUser) {
      return errorResponse("User information not found", 401);
    }
    const selectColumns = tagSchema.hasCreatorId ? "id, name, creator_id" : "id, name, NULL as creator_id";
    const checkStmt = db.prepare(`SELECT ${selectColumns} FROM tags WHERE id = ?`);
    const tag = await checkStmt.bind(tagId).first();
    if (!tag) {
      return errorResponse("Tag not found", 404);
    }
    if (tagSchema.hasCreatorId && tag.creator_id !== null && tag.creator_id !== currentUser.id) {
      return errorResponse("Permission denied: You can only delete tags you created", 403);
    }
    const deleteStmt = db.prepare("DELETE FROM tags WHERE id = ?");
    const result = await deleteStmt.bind(tagId).run();
    if (result.changes === 0) {
      return errorResponse("Failed to delete tag", 500);
    }
    return jsonResponse({
      message: "Tag deleted successfully",
      name: tag.name
    });
  } catch (error) {
    console.error("Error deleting tag:", error);
    return errorResponse("Failed to delete tag", 500);
  }
});
var tags_default = app4;

// src/handlers/users.js
init_auth();
var app5 = new Hono2();
app5.get("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const stmt = db.prepare(`
      SELECT id, username, nickname, email, avatar_url, created_ts, is_admin, role, row_status
      FROM users
      ORDER BY created_ts ASC
    `);
    const { results } = await stmt.all();
    const transformedResults = results.map((user) => {
      const transformed = {
        ...user,
        avatarUrl: user.avatar_url,
        rowStatus: user.row_status === 0 ? "NORMAL" : "ARCHIVED"
      };
      delete transformed.avatar_url;
      delete transformed.row_status;
      return transformed;
    });
    return jsonResponse(transformedResults);
  } catch (error) {
    console.error("Error fetching users:", error);
    return errorResponse("Failed to fetch users", 500);
  }
});
app5.post("/", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    if (!body.username || !body.nickname || !body.password) {
      return errorResponse("Username, nickname and password are required");
    }
    if (body.password.length < 6) {
      return errorResponse("Password must be at least 6 characters long");
    }
    const userCountStmt = db.prepare("SELECT COUNT(*) as count FROM users");
    const userCount = await userCountStmt.first();
    const isFirstUser = userCount.count === 0;
    if (!isFirstUser) {
      const authError = await requireAdmin(c);
      if (authError) {
        const settingStmt = db.prepare("SELECT value FROM settings WHERE key = 'allow_registration'");
        const setting = await settingStmt.first();
        if (setting && setting.value === "false") {
          return errorResponse("Registration is currently disabled", 403);
        }
      }
    }
    const existingUserStmt = db.prepare("SELECT id FROM users WHERE username = ?");
    const existingUser = await existingUserStmt.bind(body.username).first();
    if (existingUser) {
      return errorResponse("Username already exists");
    }
    const hashedPassword = await hashPassword(body.password);
    let userRole = isFirstUser ? "host" : "user";
    if (body.role && !isFirstUser) {
      const currentUser = c.get("user");
      if (currentUser && canModifyRole(currentUser.role, body.role)) {
        if (isValidRole(body.role)) {
          userRole = body.role;
        } else {
          return errorResponse("Invalid role. Must be host, admin, or user", 400);
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
      ["host", "admin"].includes(userRole) ? 1 : 0,
      userRole
    ).run();
    return jsonResponse({
      id: result.meta.last_row_id,
      username: body.username,
      nickname: body.nickname,
      email: body.email,
      is_admin: ["host", "admin"].includes(userRole),
      role: userRole,
      rowStatus: "NORMAL",
      message: isFirstUser ? "First user created as host" : "User created successfully"
    }, 201);
  } catch (error) {
    console.error("Error creating user:", error);
    return errorResponse("Failed to create user", 500);
  }
});
app5.post("/login", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    if (!body.username || !body.password) {
      return errorResponse("Username and password are required");
    }
    const settingStmt = db.prepare("SELECT value FROM settings WHERE key = 'disable-password-login'");
    const setting = await settingStmt.first();
    if (setting && setting.value === "true") {
      return errorResponse("Password login is disabled. Please use SSO or other authentication methods.", 403);
    }
    await cleanupExpiredSessions(db);
    const stmt = db.prepare(`
      SELECT id, username, nickname, password_hash, email, avatar_url, is_admin, role
      FROM users
      WHERE username = ?
    `);
    const user = await stmt.bind(body.username).first();
    if (!user) {
      return errorResponse("Invalid username or password", 401);
    }
    const isValidPassword = await verifyPassword(body.password, user.password_hash);
    if (!isValidPassword) {
      return errorResponse("Invalid username or password", 401);
    }
    if (needsPasswordUpgrade(user.password_hash)) {
      console.log(`Upgrading password hash for user ${user.username}`);
      const newHash = await hashPassword(body.password);
      await upgradePasswordHash(db, user.id, newHash);
    }
    const ipAddress = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || null;
    const userAgent = c.req.header("User-Agent") || null;
    const sessionToken = await createSession(db, user.id, ipAddress, userAgent);
    if (!sessionToken) {
      return errorResponse("Failed to create session", 500);
    }
    return jsonResponse({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        nickname: user.nickname,
        email: user.email,
        avatarUrl: user.avatar_url,
        is_admin: Boolean(user.is_admin),
        role: user.role || (user.is_admin ? "admin" : "user")
      },
      token: sessionToken
    });
  } catch (error) {
    console.error("Error during login:", error);
    return errorResponse("Login failed", 500);
  }
});
app5.post("/logout", async (c) => {
  try {
    const db = c.env.DB;
    const authHeader = c.req.header("Authorization");
    const token = authHeader?.replace("Bearer ", "") || c.req.header("X-Token") || c.req.query("token");
    if (token && /^[0-9a-f]{64}$/.test(token)) {
      await deleteSession(db, token);
    }
    return jsonResponse({
      success: true,
      message: "Logout successful"
    });
  } catch (error) {
    console.error("Error during logout:", error);
    return errorResponse("Logout failed", 500);
  }
});
app5.put("/:id/password", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    const currentUser = c.get("user");
    if (!currentUser) {
      return errorResponse("Valid user required", 403);
    }
    if (!body.newPassword) {
      return errorResponse("New password is required");
    }
    if (body.newPassword.length < 6) {
      return errorResponse("New password must be at least 6 characters long");
    }
    const userStmt = db.prepare("SELECT id, role, password_hash FROM users WHERE id = ?");
    const user = await userStmt.bind(id).first();
    if (!user) {
      return errorResponse("User not found", 404);
    }
    const isSelf = Number(currentUser.id) === Number(id);
    const currentUserRole = currentUser.role || (currentUser.is_admin ? "admin" : "user");
    const canResetPassword = canModifyRole(currentUserRole, user.role);
    if (!isSelf && !canResetPassword) {
      return errorResponse("Permission denied: Cannot modify this user", 403);
    }
    if (isSelf) {
      if (!body.currentPassword) {
        return errorResponse("Current password is required");
      }
      const isValidPassword = await verifyPassword(body.currentPassword, user.password_hash);
      if (!isValidPassword) {
        return errorResponse("Current password is incorrect", 400);
      }
    }
    const newHashedPassword = await hashPassword(body.newPassword);
    const updateStmt = db.prepare(`
      UPDATE users 
      SET password_hash = ?, updated_ts = ?
      WHERE id = ?
    `);
    const result = await updateStmt.bind(
      newHashedPassword,
      Math.floor(Date.now() / 1e3),
      id
    ).run();
    if (result.changes === 0) {
      return errorResponse("Failed to update password", 500);
    }
    return jsonResponse({
      message: "Password updated successfully"
    });
  } catch (error) {
    console.error("Error updating password:", error);
    return errorResponse("Failed to update password", 500);
  }
});
app5.put("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    const currentUser = c.get("user");
    if (body.nickname === void 0 && body.email === void 0 && body.avatarUrl === void 0 && body.role === void 0 && body.rowStatus === void 0) {
      return errorResponse("At least nickname, email, avatarUrl, role or rowStatus must be provided");
    }
    const targetUserStmt = db.prepare("SELECT id, role FROM users WHERE id = ?");
    const targetUser = await targetUserStmt.bind(id).first();
    if (!targetUser) {
      return errorResponse("User not found", 404);
    }
    const updateFields = [];
    const updateValues = [];
    if (body.nickname) {
      updateFields.push("nickname = ?");
      updateValues.push(body.nickname);
    }
    if (body.email !== void 0) {
      updateFields.push("email = ?");
      updateValues.push(body.email || null);
    }
    if (body.avatarUrl !== void 0) {
      updateFields.push("avatar_url = ?");
      updateValues.push(body.avatarUrl || null);
    }
    if (body.role !== void 0) {
      if (!isValidRole(body.role)) {
        return errorResponse("Invalid role. Must be host, admin, or user", 400);
      }
      if (!canModifyRole(currentUser.role, body.role)) {
        return errorResponse("Permission denied: Cannot modify this role", 403);
      }
      if (targetUser.role === "host" && currentUser.role !== "host") {
        return errorResponse("Permission denied: Cannot modify host user", 403);
      }
      updateFields.push("role = ?");
      updateValues.push(body.role);
      updateFields.push("is_admin = ?");
      updateValues.push(["host", "admin"].includes(body.role) ? 1 : 0);
    }
    if (body.rowStatus !== void 0) {
      const validStatuses = ["NORMAL", "ARCHIVED"];
      if (!validStatuses.includes(body.rowStatus)) {
        return errorResponse("Invalid rowStatus. Must be NORMAL or ARCHIVED", 400);
      }
      updateFields.push("row_status = ?");
      updateValues.push(body.rowStatus === "NORMAL" ? 0 : 1);
    }
    updateFields.push("updated_ts = ?");
    updateValues.push(Math.floor(Date.now() / 1e3));
    updateValues.push(id);
    const stmt = db.prepare(`
      UPDATE users
      SET ${updateFields.join(", ")}
      WHERE id = ?
    `);
    const result = await stmt.bind(...updateValues).run();
    const userStmt = db.prepare("SELECT id, username, nickname, email, avatar_url, is_admin, role, row_status FROM users WHERE id = ?");
    const user = await userStmt.bind(id).first();
    if (!user) {
      return errorResponse("User not found after update", 500);
    }
    const responseUser = {
      ...user,
      avatarUrl: user.avatar_url,
      rowStatus: user.row_status === 0 ? "NORMAL" : "ARCHIVED"
    };
    delete responseUser.avatar_url;
    delete responseUser.row_status;
    return jsonResponse({
      ...responseUser,
      message: "User updated successfully"
    });
  } catch (error) {
    console.error("Error updating user:", error);
    return errorResponse("Failed to update user", 500);
  }
});
app5.patch("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    const currentUser = c.get("user");
    console.log("PATCH /user/:id - Request body:", JSON.stringify(body));
    console.log("PATCH /user/:id - User ID:", id);
    console.log("PATCH /user/:id - Current user:", currentUser.id);
    if (body.nickname === void 0 && body.email === void 0 && body.avatarUrl === void 0 && body.role === void 0 && body.rowStatus === void 0) {
      return errorResponse("At least nickname, email, avatarUrl, role or rowStatus must be provided");
    }
    const targetUserStmt = db.prepare("SELECT id, role FROM users WHERE id = ?");
    const targetUser = await targetUserStmt.bind(id).first();
    if (!targetUser) {
      return errorResponse("User not found", 404);
    }
    const updateFields = [];
    const updateValues = [];
    if (body.nickname !== void 0) {
      console.log("Adding nickname to update:", body.nickname);
      updateFields.push("nickname = ?");
      updateValues.push(body.nickname);
    }
    if (body.email !== void 0) {
      console.log("Adding email to update:", body.email);
      updateFields.push("email = ?");
      updateValues.push(body.email || null);
    }
    if (body.avatarUrl !== void 0) {
      console.log("Adding avatarUrl to update:", body.avatarUrl);
      updateFields.push("avatar_url = ?");
      updateValues.push(body.avatarUrl || null);
    }
    if (body.role !== void 0) {
      if (!isValidRole(body.role)) {
        return errorResponse("Invalid role. Must be host, admin, or user", 400);
      }
      if (!canModifyRole(currentUser.role, body.role)) {
        return errorResponse("Permission denied: Cannot modify this role", 403);
      }
      if (targetUser.role === "host" && currentUser.role !== "host") {
        return errorResponse("Permission denied: Cannot modify host user", 403);
      }
      updateFields.push("role = ?");
      updateValues.push(body.role);
      updateFields.push("is_admin = ?");
      updateValues.push(["host", "admin"].includes(body.role) ? 1 : 0);
    }
    if (body.rowStatus !== void 0) {
      const validStatuses = ["NORMAL", "ARCHIVED"];
      if (!validStatuses.includes(body.rowStatus)) {
        return errorResponse("Invalid rowStatus. Must be NORMAL or ARCHIVED", 400);
      }
      updateFields.push("row_status = ?");
      updateValues.push(body.rowStatus === "NORMAL" ? 0 : 1);
    }
    updateFields.push("updated_ts = ?");
    updateValues.push(Math.floor(Date.now() / 1e3));
    updateValues.push(id);
    const stmt = db.prepare(`
      UPDATE users
      SET ${updateFields.join(", ")}
      WHERE id = ?
    `);
    const result = await stmt.bind(...updateValues).run();
    const userStmt = db.prepare("SELECT id, username, nickname, email, avatar_url, is_admin, role, row_status FROM users WHERE id = ?");
    const user = await userStmt.bind(id).first();
    if (!user) {
      return errorResponse("User not found after update", 500);
    }
    const responseUser = {
      ...user,
      avatarUrl: user.avatar_url,
      rowStatus: user.row_status === 0 ? "NORMAL" : "ARCHIVED"
    };
    delete responseUser.avatar_url;
    delete responseUser.row_status;
    return jsonResponse({
      ...responseUser,
      message: "User updated successfully"
    });
  } catch (error) {
    console.error("Error updating user:", error);
    return errorResponse("Failed to update user", 500);
  }
});
app5.delete("/:id", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const currentUser = c.get("user");
    const userStmt = db.prepare("SELECT id, role FROM users WHERE id = ?");
    const user = await userStmt.bind(id).first();
    if (!user) {
      return errorResponse("User not found", 404);
    }
    if (user.role === "host") {
      return errorResponse("Cannot delete host user", 403);
    }
    if (currentUser.role === "admin" && user.role === "admin") {
      return errorResponse("Permission denied: Cannot delete other admin users", 403);
    }
    const deleteSessionsStmt = db.prepare("DELETE FROM sessions WHERE user_id = ?");
    await deleteSessionsStmt.bind(id).run();
    const deleteUserStmt = db.prepare("DELETE FROM users WHERE id = ?");
    const result = await deleteUserStmt.bind(id).run();
    if (result.changes === 0) {
      return errorResponse("Failed to delete user", 500);
    }
    return jsonResponse({
      message: "User deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting user:", error);
    return errorResponse("Failed to delete user", 500);
  }
});
var users_default = app5;

// src/handlers/userSettings.js
init_auth();
var app6 = new Hono2();
app6.get("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const stmt = db.prepare(`
      SELECT locale, appearance, memo_visibility, telegram_user_id
      FROM user_settings
      WHERE user_id = ?
    `);
    let setting = await stmt.bind(currentUser.id).first();
    if (!setting) {
      const createStmt = db.prepare(`
        INSERT INTO user_settings (user_id, locale, appearance, memo_visibility, telegram_user_id)
        VALUES (?, ?, ?, ?, ?)
      `);
      await createStmt.bind(
        currentUser.id,
        "en",
        "auto",
        "PRIVATE",
        ""
      ).run();
      setting = {
        locale: "en",
        appearance: "auto",
        memo_visibility: "PRIVATE",
        telegram_user_id: ""
      };
    }
    return jsonResponse({
      locale: setting.locale,
      appearance: setting.appearance,
      memoVisibility: setting.memo_visibility,
      telegramUserId: setting.telegram_user_id || ""
    });
  } catch (error) {
    console.error("Error fetching user settings:", error);
    return errorResponse("Failed to fetch user settings", 500);
  }
});
app6.post("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const body = await c.req.json();
    console.log("Updating user settings with body:", body);
    console.log("Current user:", currentUser);
    const locale = body.locale !== void 0 ? body.locale : "en";
    const appearance = body.appearance !== void 0 ? body.appearance : "auto";
    const memoVisibility = body.memoVisibility !== void 0 ? body.memoVisibility : "PRIVATE";
    const telegramUserId = body.telegramUserId !== void 0 ? body.telegramUserId : "";
    console.log("Parsed values:", { locale, appearance, memoVisibility, telegramUserId });
    const validAppearances = ["auto", "light", "dark"];
    if (!validAppearances.includes(appearance)) {
      return errorResponse("Invalid appearance value. Must be: auto, light, or dark", 400);
    }
    const validVisibilities = ["PUBLIC", "PROTECTED", "PRIVATE"];
    if (!validVisibilities.includes(memoVisibility)) {
      return errorResponse("Invalid memoVisibility value. Must be: PUBLIC, PROTECTED, or PRIVATE", 400);
    }
    const checkStmt = db.prepare("SELECT id FROM user_settings WHERE user_id = ?");
    const existingSetting = await checkStmt.bind(currentUser.id).first();
    console.log("Existing setting:", existingSetting);
    let result;
    if (existingSetting) {
      const updateStmt = db.prepare(`
        UPDATE user_settings
        SET locale = ?, appearance = ?, memo_visibility = ?, telegram_user_id = ?, updated_ts = ?
        WHERE user_id = ?
      `);
      result = await updateStmt.bind(
        locale,
        appearance,
        memoVisibility,
        telegramUserId,
        Math.floor(Date.now() / 1e3),
        currentUser.id
      ).run();
    } else {
      const insertStmt = db.prepare(`
        INSERT INTO user_settings (user_id, locale, appearance, memo_visibility, telegram_user_id)
        VALUES (?, ?, ?, ?, ?)
      `);
      result = await insertStmt.bind(
        currentUser.id,
        locale,
        appearance,
        memoVisibility,
        telegramUserId
      ).run();
    }
    console.log("Update/Insert result:", result);
    if (result.changes === 0 && existingSetting) {
      return errorResponse("Failed to update user settings", 500);
    }
    return jsonResponse({
      locale,
      appearance,
      memoVisibility,
      telegramUserId,
      message: "User settings updated successfully"
    });
  } catch (error) {
    console.error("Error updating user settings:", error);
    console.error("Error stack:", error.stack);
    return errorResponse("Failed to update user settings", 500);
  }
});
var userSettings_default = app6;

// src/handlers/resources.js
init_auth();
var app7 = new Hono2();
app7.get("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const limit = parseInt(c.req.query("limit")) || 20;
    const offset = parseInt(c.req.query("offset")) || 0;
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
    const formattedResults = results.map((r) => ({
      id: r.id,
      filename: r.filename,
      filepath: r.filepath,
      type: r.type,
      size: r.size,
      createdTs: r.created_ts * 1e3,
      // 转换为毫秒并使用 camelCase
      creatorUsername: r.creator_username,
      creatorName: r.creator_name,
      memoId: r.memoId
      // 只有关联到正常memo时才有值，否则为 null
    }));
    return jsonResponse(formattedResults);
  } catch (error) {
    console.error("Error fetching resources:", error);
    return errorResponse("Failed to fetch resources", 500);
  }
});
app7.get("/:id/file", async (c) => {
  try {
    const db = c.env.DB;
    const bucket = c.env.BUCKET;
    const id = c.req.param("id");
    const stmt = db.prepare(`
      SELECT id, filename, filepath, type, size
      FROM resources
      WHERE id = ?
    `);
    const resource = await stmt.bind(id).first();
    if (!resource) {
      return errorResponse("Resource not found", 404);
    }
    let objectKey = resource.filepath;
    if (objectKey.startsWith("http")) {
      const url = new URL(objectKey);
      objectKey = url.pathname.substring(1);
    }
    const object = await bucket.get(objectKey);
    if (!object) {
      return errorResponse("File not found in storage", 404);
    }
    return new Response(object.body, {
      headers: {
        "Content-Type": resource.type || "application/octet-stream",
        "Content-Length": resource.size?.toString() || "",
        "Content-Disposition": `inline; filename="${encodeURIComponent(resource.filename)}"`,
        "Cache-Control": "public, max-age=31536000"
      }
    });
  } catch (error) {
    console.error("Error proxying resource:", error);
    return errorResponse("Failed to access resource", 500);
  }
});
app7.get("/:id", async (c) => {
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const stmt = db.prepare(`
      SELECT id, filename, filepath, type, size, created_ts
      FROM resources
      WHERE id = ?
    `);
    const resource = await stmt.bind(id).first();
    if (!resource) {
      return errorResponse("Resource not found", 404);
    }
    if (resource.filepath.startsWith("http")) {
      return Response.redirect(resource.filepath, 302);
    }
    return jsonResponse(resource);
  } catch (error) {
    console.error("Error fetching resource:", error);
    return errorResponse("Failed to fetch resource", 500);
  }
});
app7.post("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const bucket = c.env.BUCKET;
    const formData = await c.req.formData();
    const file = formData.get("file");
    if (!file) {
      return errorResponse("No file provided");
    }
    const MAX_FILE_SIZE = 32 * 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
      return errorResponse(`File size exceeds maximum allowed size of ${MAX_FILE_SIZE / 1024 / 1024}MB`);
    }
    const ALLOWED_TYPES = [
      // 图片
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/gif",
      "image/webp",
      "image/svg+xml",
      "image/bmp",
      "image/tiff",
      // 文档
      "application/pdf",
      "text/plain",
      "text/markdown",
      "text/html",
      "text/css",
      "text/javascript",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.ms-powerpoint",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      // 压缩文件
      "application/zip",
      "application/x-zip-compressed",
      "application/x-rar-compressed",
      "application/x-7z-compressed",
      "application/gzip",
      "application/x-tar",
      // 视频
      "video/mp4",
      "video/mpeg",
      "video/quicktime",
      "video/x-msvideo",
      "video/x-ms-wmv",
      "video/webm",
      // 音频
      "audio/mpeg",
      "audio/wav",
      "audio/ogg",
      "audio/webm",
      "audio/mp4",
      // 其他
      "application/json",
      "text/csv",
      "application/xml",
      "text/xml"
    ];
    if (!ALLOWED_TYPES.includes(file.type)) {
      return errorResponse(`File type '${file.type}' is not allowed. Allowed types: images, videos, audio, PDF, documents, and archives.`);
    }
    const filename = file.name;
    if (filename.includes("..") || filename.includes("/") || filename.includes("\\")) {
      return errorResponse("Invalid filename");
    }
    let creatorId = c.get("user")?.id;
    if (!creatorId) {
      creatorId = await ensureDefaultUser(c.env.DB);
    }
    const timestamp = Date.now();
    const fileExtension = file.name.split(".").pop();
    const uniqueFilename = `${creatorId}_${timestamp}.${fileExtension}`;
    const uploadResult = await bucket.put(uniqueFilename, file.stream(), {
      httpMetadata: {
        contentType: file.type
      }
    });
    if (!uploadResult) {
      return errorResponse("Failed to upload file", 500);
    }
    const stmt = db.prepare(`
      INSERT INTO resources (creator_id, filename, filepath, type, size)
      VALUES (?, ?, ?, ?, ?)
    `);
    const result = await stmt.bind(
      creatorId,
      file.name,
      uniqueFilename,
      // 存储文件名
      file.type,
      file.size
    ).run();
    const resourceId = result.meta.last_row_id;
    const workerUrl = new URL(c.req.url).origin;
    const fileUrl = `${workerUrl}/${uniqueFilename}`;
    return jsonResponse({
      id: resourceId,
      filename: file.name,
      filepath: fileUrl,
      // 返回完整 URL
      type: file.type,
      size: file.size,
      message: "File uploaded successfully"
    }, 201);
  } catch (error) {
    console.error("Error uploading resource:", error);
    return errorResponse("Failed to upload resource", 500);
  }
});
var resources_default = app7;

// src/handlers/settings.js
init_auth();
var app8 = new Hono2();
app8.get("/public", async (c) => {
  try {
    const db = c.env.DB;
    const stmt = db.prepare(`
      SELECT key, value
      FROM settings
      WHERE key IN ('site_title', 'site_avatar', 'allow_registration')
    `);
    const { results } = await stmt.all();
    const settings = {};
    results.forEach((row) => {
      settings[row.key] = row.value;
    });
    return jsonResponse(settings);
  } catch (error) {
    console.error("Error fetching public settings:", error);
    return errorResponse("Failed to fetch settings", 500);
  }
});
app8.get("/", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const stmt = db.prepare("SELECT * FROM settings ORDER BY key");
    const { results } = await stmt.all();
    const formattedResults = results.map((setting) => ({
      ...setting,
      name: setting.key
    }));
    return jsonResponse(formattedResults);
  } catch (error) {
    console.error("Error fetching settings:", error);
    return errorResponse("Failed to fetch settings", 500);
  }
});
app8.post("/", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const name = body.name || body.key;
    const value = body.value;
    if (!name) {
      return errorResponse("Setting name is required", 400);
    }
    const checkStmt = db.prepare("SELECT id FROM settings WHERE key = ?");
    const existing = await checkStmt.bind(name).first();
    let result;
    if (existing) {
      const updateStmt = db.prepare(`
        UPDATE settings
        SET value = ?, updated_ts = strftime('%s', 'now')
        WHERE key = ?
      `);
      result = await updateStmt.bind(value, name).run();
    } else {
      const insertStmt = db.prepare(`
        INSERT INTO settings (key, value, description)
        VALUES (?, ?, ?)
      `);
      result = await insertStmt.bind(name, value, body.description || "").run();
    }
    return jsonResponse({
      name,
      value,
      message: "Setting saved successfully"
    });
  } catch (error) {
    console.error("Error saving setting:", error);
    return errorResponse("Failed to save setting", 500);
  }
});
app8.put("/:key", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const key = c.req.param("key");
    const { value } = await c.req.json();
    const stmt = db.prepare(`
      UPDATE settings
      SET value = ?, updated_ts = strftime('%s', 'now')
      WHERE key = ?
    `);
    await stmt.bind(value, key).run();
    return jsonResponse({ message: "Setting updated successfully", key, value });
  } catch (error) {
    console.error("Error updating setting:", error);
    return errorResponse("Failed to update setting", 500);
  }
});
var settings_default = app8;

// src/handlers/rss.js
init_auth();
var app9 = new Hono2();
function escapeXml(text) {
  if (!text)
    return "";
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}
__name(escapeXml, "escapeXml");
function generateRssFeed(options) {
  const {
    title,
    description,
    link,
    baseUrl,
    // 用于构建item链接的基础URL
    items = []
  } = options;
  const now = (/* @__PURE__ */ new Date()).toUTCString();
  const itemBaseUrl = baseUrl || link;
  let rssItems = "";
  for (const item of items) {
    const pubDate = new Date(item.createdTs * 1e3).toUTCString();
    let contentHtml = escapeXml(item.content || "");
    if (item.resourceList && item.resourceList.length > 0) {
      const imageResources = item.resourceList.filter((r) => r.type && r.type.startsWith("image/"));
      if (imageResources.length > 0) {
        contentHtml += "\n\n";
        imageResources.forEach((resource) => {
          const imageUrl = resource.filepath.startsWith("http") ? resource.filepath : `${itemBaseUrl}${resource.filepath}`;
          contentHtml += `&lt;img src="${escapeXml(imageUrl)}" alt="${escapeXml(resource.filename)}" style="max-width: 100%; height: auto;" /&gt;
`;
        });
      }
    }
    rssItems += `
    <item>
      <title>${escapeXml(item.title || `Memo #${item.id}`)}</title>
      <link>${escapeXml(itemBaseUrl)}/m/${item.id}</link>
      <guid isPermaLink="true">${escapeXml(itemBaseUrl)}/m/${item.id}</guid>
      <pubDate>${pubDate}</pubDate>
      <description><![CDATA[${contentHtml}]]></description>
      ${item.creatorName ? `<author>${escapeXml(item.creatorName)}</author>` : ""}
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
__name(generateRssFeed, "generateRssFeed");
async function getBaseUrl(db, request) {
  try {
    const stmt = db.prepare("SELECT value FROM settings WHERE key = ?");
    const setting = await stmt.bind("instance-url").first();
    if (setting && setting.value) {
      return setting.value.replace(/\/$/, "");
    }
  } catch (error) {
    console.error("Error reading instance-url from settings:", error);
  }
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}
__name(getBaseUrl, "getBaseUrl");
app9.get("/rss.xml", async (c) => {
  try {
    const db = c.env.DB;
    const baseUrl = await getBaseUrl(db, c.req.raw);
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
    for (let memo of memos) {
      const resourceStmt = db.prepare(`
        SELECT r.id, r.filename, r.filepath, r.type, r.size
        FROM resources r
        JOIN memo_resources mr ON r.id = mr.resource_id
        WHERE mr.memo_id = ?
      `);
      const { results: resources } = await resourceStmt.bind(memo.id).all();
      memo.resourceList = (resources || []).map((r) => ({
        ...r,
        filepath: r.filepath.startsWith("http") || r.filepath.startsWith("/api/") ? r.filepath : `/api/v1/resource/${r.id}/file`
      }));
    }
    const rssFeed = generateRssFeed({
      title: "Memos - \u5168\u7AD9\u52A8\u6001",
      description: "\u6700\u65B0\u7684\u5907\u5FD8\u5F55\u66F4\u65B0",
      link: baseUrl,
      items: memos
    });
    return new Response(rssFeed, {
      headers: {
        "Content-Type": "application/rss+xml; charset=utf-8",
        "Cache-Control": "public, max-age=3600"
      }
    });
  } catch (error) {
    console.error("Error generating RSS feed:", error);
    return errorResponse("Failed to generate RSS feed", 500);
  }
});
app9.get("/u/:userId/rss.xml", async (c) => {
  try {
    const db = c.env.DB;
    const userId = c.req.param("userId");
    const baseUrl = await getBaseUrl(db, c.req.raw);
    const userStmt = db.prepare("SELECT id, username, nickname FROM users WHERE id = ?");
    const user = await userStmt.bind(userId).first();
    if (!user) {
      return errorResponse("User not found", 404);
    }
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
    for (let memo of memos) {
      const resourceStmt = db.prepare(`
        SELECT r.id, r.filename, r.filepath, r.type, r.size
        FROM resources r
        JOIN memo_resources mr ON r.id = mr.resource_id
        WHERE mr.memo_id = ?
      `);
      const { results: resources } = await resourceStmt.bind(memo.id).all();
      memo.resourceList = (resources || []).map((r) => ({
        ...r,
        filepath: r.filepath.startsWith("http") || r.filepath.startsWith("/api/") ? r.filepath : `/api/v1/resource/${r.id}/file`
      }));
    }
    const rssFeed = generateRssFeed({
      title: `Memos - ${user.nickname || user.username} \u7684\u52A8\u6001`,
      description: `${user.nickname || user.username} \u7684\u6700\u65B0\u5907\u5FD8\u5F55`,
      link: `${baseUrl}/u/${user.username}`,
      // Channel link 指向用户页面
      baseUrl,
      // Item links 使用基础URL（不含 /u/username）
      items: memos
    });
    return new Response(rssFeed, {
      headers: {
        "Content-Type": "application/rss+xml; charset=utf-8",
        "Cache-Control": "public, max-age=3600"
      }
    });
  } catch (error) {
    console.error("Error generating user RSS feed:", error);
    return errorResponse("Failed to generate RSS feed", 500);
  }
});
var rss_default = app9;

// src/handlers/accessTokens.js
init_auth();
init_jwt();
var app10 = new Hono2();
app10.get("/:username/access-tokens", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const username = c.req.param("username");
    const currentUser = c.get("user");
    if (currentUser.username !== username) {
      return errorResponse("Forbidden", 403);
    }
    const stmt = db.prepare(`
      SELECT id, name, token, created_ts, expires_ts, is_active
      FROM api_tokens
      WHERE user_id = ? AND is_active = 1
      ORDER BY created_ts DESC
    `);
    const { results } = await stmt.bind(currentUser.id).all();
    const accessTokens = results.map((token) => ({
      name: `users/${username}/accessTokens/${token.id}`,
      accessToken: token.token,
      description: token.name,
      issuedAt: new Date(token.created_ts * 1e3).toISOString(),
      expiresAt: token.expires_ts ? new Date(token.expires_ts * 1e3).toISOString() : null
    }));
    return jsonResponse(accessTokens);
  } catch (error) {
    console.error("Error fetching access tokens:", error);
    return errorResponse("Failed to fetch access tokens", 500);
  }
});
app10.post("/:username/access-tokens", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const username = c.req.param("username");
    const currentUser = c.get("user");
    const body = await c.req.json();
    if (currentUser.username !== username) {
      return errorResponse("Forbidden", 403);
    }
    if (!body.description) {
      return errorResponse("Description is required", 400);
    }
    const now = Math.floor(Date.now() / 1e3);
    let expiresTs = null;
    let expiresIn = 100 * 365 * 24 * 60 * 60;
    if (body.expiresAt) {
      expiresTs = Math.floor(new Date(body.expiresAt).getTime() / 1e3);
      expiresIn = expiresTs - now;
    }
    const roleMap = { "host": 1, "admin": 2, "user": 3 };
    const roleValue = roleMap[currentUser.role] || 3;
    const jwtSecret = getJWTSecret(c.env);
    const token = await generateJWT({
      id: currentUser.id,
      username: currentUser.username,
      nickname: currentUser.nickname,
      email: currentUser.email || "",
      role: roleValue,
      tokenType: "access_token",
      // 标记为 Access Token
      description: body.description
    }, jwtSecret, expiresIn);
    const stmt = db.prepare(`
      INSERT INTO api_tokens (user_id, name, token, created_ts, expires_ts)
      VALUES (?, ?, ?, ?, ?)
    `);
    const result = await stmt.bind(
      currentUser.id,
      body.description,
      token,
      now,
      expiresTs
    ).run();
    const tokenId = result.meta.last_row_id;
    return jsonResponse({
      name: `users/${username}/accessTokens/${tokenId}`,
      accessToken: token,
      description: body.description,
      issuedAt: new Date(now * 1e3).toISOString(),
      expiresAt: expiresTs ? new Date(expiresTs * 1e3).toISOString() : null
    }, 201);
  } catch (error) {
    console.error("Error creating access token:", error);
    return errorResponse("Failed to create access token", 500);
  }
});
app10.delete("/:username/access-tokens/:token", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const username = c.req.param("username");
    const token = c.req.param("token");
    const currentUser = c.get("user");
    if (currentUser.username !== username) {
      return errorResponse("Forbidden", 403);
    }
    const stmt = db.prepare(`
      UPDATE api_tokens
      SET is_active = 0
      WHERE user_id = ? AND token = ?
    `);
    await stmt.bind(currentUser.id, token).run();
    return jsonResponse({ message: "Access token deleted successfully" });
  } catch (error) {
    console.error("Error deleting access token:", error);
    return errorResponse("Failed to delete access token", 500);
  }
});
var accessTokens_default = app10;

// src/handlers/webhooks.js
init_auth();
var app11 = new Hono2();
app11.get("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const stmt = db.prepare(`
      SELECT id, name, url, created_ts
      FROM webhooks
      WHERE user_id = ?
      ORDER BY id DESC
    `);
    const { results: webhooks } = await stmt.bind(currentUser.id).all();
    return jsonResponse(webhooks || []);
  } catch (error) {
    console.error("Error fetching webhooks:", error);
    return errorResponse("Failed to fetch webhooks", 500);
  }
});
app11.post("/", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const body = await c.req.json();
    console.log("Creating webhook with body:", body);
    console.log("Current user:", currentUser);
    if (!body.name || !body.url) {
      console.error("Missing required fields:", { name: body.name, url: body.url });
      return errorResponse("Name and URL are required", 400);
    }
    try {
      new URL(body.url);
    } catch (e) {
      console.error("Invalid URL format:", body.url, e);
      return errorResponse("Invalid URL format", 400);
    }
    const now = Math.floor(Date.now() / 1e3);
    const insertStmt = db.prepare(`
      INSERT INTO webhooks (user_id, name, url, created_ts)
      VALUES (?, ?, ?, ?)
    `);
    const result = await insertStmt.bind(
      currentUser.id,
      body.name,
      body.url,
      now
    ).run();
    console.log("Insert result:", result);
    const getStmt = db.prepare("SELECT id, name, url, created_ts FROM webhooks WHERE id = ?");
    const webhook = await getStmt.bind(result.meta.last_row_id).first();
    console.log("Created webhook:", webhook);
    return jsonResponse(webhook);
  } catch (error) {
    console.error("Error creating webhook:", error);
    console.error("Error stack:", error.stack);
    return errorResponse("Failed to create webhook: " + error.message, 500);
  }
});
app11.get("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const webhookId = c.req.param("id");
    const stmt = db.prepare(`
      SELECT id, name, url, created_ts
      FROM webhooks
      WHERE id = ? AND user_id = ?
    `);
    const webhook = await stmt.bind(webhookId, currentUser.id).first();
    if (!webhook) {
      return errorResponse("Webhook not found", 404);
    }
    return jsonResponse(webhook);
  } catch (error) {
    console.error("Error fetching webhook:", error);
    return errorResponse("Failed to fetch webhook", 500);
  }
});
app11.patch("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const webhookId = c.req.param("id");
    const body = await c.req.json();
    const checkStmt = db.prepare("SELECT id FROM webhooks WHERE id = ? AND user_id = ?");
    const existing = await checkStmt.bind(webhookId, currentUser.id).first();
    if (!existing) {
      return errorResponse("Webhook not found", 404);
    }
    if (body.url) {
      try {
        new URL(body.url);
      } catch (e) {
        return errorResponse("Invalid URL format", 400);
      }
    }
    const updateStmt = db.prepare(`
      UPDATE webhooks
      SET name = COALESCE(?, name),
          url = COALESCE(?, url)
      WHERE id = ? AND user_id = ?
    `);
    await updateStmt.bind(
      body.name || null,
      body.url || null,
      webhookId,
      currentUser.id
    ).run();
    const getStmt = db.prepare("SELECT id, name, url, created_ts FROM webhooks WHERE id = ?");
    const webhook = await getStmt.bind(webhookId).first();
    return jsonResponse(webhook);
  } catch (error) {
    console.error("Error updating webhook:", error);
    return errorResponse("Failed to update webhook", 500);
  }
});
app11.delete("/:id", async (c) => {
  const authError = await requireAuth(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const currentUser = c.get("user");
    const webhookId = c.req.param("id");
    const deleteStmt = db.prepare("DELETE FROM webhooks WHERE id = ? AND user_id = ?");
    const result = await deleteStmt.bind(webhookId, currentUser.id).run();
    if (result.changes === 0) {
      return errorResponse("Webhook not found", 404);
    }
    return jsonResponse({ message: "Webhook deleted successfully" });
  } catch (error) {
    console.error("Error deleting webhook:", error);
    return errorResponse("Failed to delete webhook", 500);
  }
});
var webhooks_default = app11;

// src/handlers/identityProviders.js
init_auth();
var app12 = new Hono2();
app12.get("/public", async (c) => {
  try {
    const db = c.env.DB;
    const stmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config
      FROM identity_providers
      ORDER BY created_ts ASC
    `);
    const { results } = await stmt.all();
    const safeResults = results.map((idp) => {
      try {
        const config = JSON.parse(idp.config);
        if (config.oauth2Config && config.oauth2Config.clientSecret) {
          config.oauth2Config.clientSecret = "";
        }
        if (config.clientSecret) {
          config.clientSecret = "";
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
    console.error("Error fetching public identity providers:", error);
    return errorResponse("Failed to fetch identity providers", 500);
  }
});
app12.get("/", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const stmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config, created_ts, updated_ts
      FROM identity_providers
      ORDER BY created_ts ASC
    `);
    const { results } = await stmt.all();
    const safeResults = results.map((idp) => {
      try {
        const config = JSON.parse(idp.config);
        if (config.clientSecret) {
          config.clientSecret = "***";
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
    console.error("Error fetching identity providers:", error);
    return errorResponse("Failed to fetch identity providers", 500);
  }
});
app12.get("/:id", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const stmt = db.prepare(`
      SELECT id, name, type, identifier_filter, config, created_ts, updated_ts
      FROM identity_providers
      WHERE id = ?
    `);
    const idp = await stmt.bind(id).first();
    if (!idp) {
      return errorResponse("Identity provider not found", 404);
    }
    try {
      const config = JSON.parse(idp.config);
      if (config.clientSecret) {
        config.clientSecret = "***";
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
    console.error("Error fetching identity provider:", error);
    return errorResponse("Failed to fetch identity provider", 500);
  }
});
app12.post("/", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    if (!body.name || !body.type) {
      return errorResponse("Name and type are required");
    }
    const validTypes = ["google", "github", "gitlab", "oidc", "OAUTH2"];
    if (!validTypes.includes(body.type)) {
      return errorResponse(`Invalid type. Must be one of: ${validTypes.join(", ")}`);
    }
    if (!body.config || typeof body.config !== "object") {
      return errorResponse("Config is required and must be an object");
    }
    let actualConfig = body.config;
    if (body.config.oauth2Config) {
      actualConfig = body.config.oauth2Config;
    }
    const requiredConfigFields = ["clientId", "clientSecret"];
    for (const field of requiredConfigFields) {
      if (!actualConfig[field]) {
        return errorResponse(`Config must include ${field}`);
      }
    }
    const stmt = db.prepare(`
      INSERT INTO identity_providers (name, type, identifier_filter, config)
      VALUES (?, ?, ?, ?)
    `);
    const result = await stmt.bind(
      body.name,
      body.type,
      body.identifierFilter || "",
      JSON.stringify(body.config)
    ).run();
    return jsonResponse({
      id: result.meta.last_row_id,
      name: body.name,
      type: body.type,
      identifierFilter: body.identifierFilter || "",
      message: "Identity provider created successfully"
    }, 201);
  } catch (error) {
    console.error("Error creating identity provider:", error);
    return errorResponse("Failed to create identity provider", 500);
  }
});
app12.patch("/:id", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const body = await c.req.json();
    const checkStmt = db.prepare("SELECT id FROM identity_providers WHERE id = ?");
    const exists = await checkStmt.bind(id).first();
    if (!exists) {
      return errorResponse("Identity provider not found", 404);
    }
    const updateFields = [];
    const updateValues = [];
    if (body.name !== void 0) {
      updateFields.push("name = ?");
      updateValues.push(body.name);
    }
    if (body.type !== void 0) {
      const validTypes = ["google", "github", "gitlab", "oidc", "OAUTH2"];
      if (!validTypes.includes(body.type)) {
        return errorResponse(`Invalid type. Must be one of: ${validTypes.join(", ")}`);
      }
      updateFields.push("type = ?");
      updateValues.push(body.type);
    }
    if (body.identifierFilter !== void 0) {
      updateFields.push("identifier_filter = ?");
      updateValues.push(body.identifierFilter);
    }
    if (body.config !== void 0) {
      if (typeof body.config !== "object") {
        return errorResponse("Config must be an object");
      }
      let actualConfig = body.config;
      if (body.config.oauth2Config) {
        actualConfig = body.config.oauth2Config;
      }
      if (actualConfig.clientSecret && !actualConfig.clientId) {
        return errorResponse("Config must include clientId when clientSecret is provided");
      }
      updateFields.push("config = ?");
      updateValues.push(JSON.stringify(body.config));
    }
    if (updateFields.length === 0) {
      return errorResponse("No fields to update");
    }
    updateFields.push("updated_ts = ?");
    updateValues.push(Math.floor(Date.now() / 1e3));
    updateValues.push(id);
    const stmt = db.prepare(`
      UPDATE identity_providers
      SET ${updateFields.join(", ")}
      WHERE id = ?
    `);
    await stmt.bind(...updateValues).run();
    return jsonResponse({
      message: "Identity provider updated successfully"
    });
  } catch (error) {
    console.error("Error updating identity provider:", error);
    return errorResponse("Failed to update identity provider", 500);
  }
});
app12.delete("/:id", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const id = c.req.param("id");
    const stmt = db.prepare("DELETE FROM identity_providers WHERE id = ?");
    const result = await stmt.bind(id).run();
    if (result.changes === 0) {
      return errorResponse("Identity provider not found", 404);
    }
    return jsonResponse({
      message: "Identity provider deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting identity provider:", error);
    return errorResponse("Failed to delete identity provider", 500);
  }
});
var identityProviders_default = app12;

// src/handlers/telegram.js
init_auth();
var app13 = new Hono2();
var VALID_VISIBILITIES = ["PRIVATE", "PROTECTED", "PUBLIC"];
function buildSettingsMap(settings) {
  const settingsMap = {};
  (settings || []).forEach((setting) => {
    settingsMap[setting.key] = setting.value;
  });
  return settingsMap;
}
__name(buildSettingsMap, "buildSettingsMap");
function buildBindingMessage(chatId, fromId, boundUser) {
  const lines = [
    "Telegram \u5DF2\u8FDE\u63A5\u5230 Memos\u3002",
    `Chat ID: ${chatId}`,
    `User ID: ${fromId}`
  ];
  if (boundUser) {
    lines.push(`\u5F53\u524D\u7ED1\u5B9A\u7528\u6237: ${boundUser.nickname || boundUser.username}`);
    lines.push("\u76F4\u63A5\u53D1\u9001\u6587\u672C\u6D88\u606F\u5373\u53EF\u521B\u5EFA memo\u3002");
  } else {
    lines.push("\u8BF7\u628A\u4E0A\u9762\u7684 User ID \u586B\u5230 Memos \u7684 Telegram UserID \u8BBE\u7F6E\u91CC\u3002");
  }
  return lines.join("\n");
}
__name(buildBindingMessage, "buildBindingMessage");
async function findUserByTelegramId(db, candidateIds) {
  const uniqueCandidateIds = [...new Set((candidateIds || []).filter((value) => value !== void 0 && value !== null && value !== "").map((value) => String(value)))];
  if (uniqueCandidateIds.length === 0) {
    return null;
  }
  const placeholders = uniqueCandidateIds.map(() => "?").join(", ");
  const stmt = db.prepare(`
    SELECT
      u.id,
      u.username,
      u.nickname,
      COALESCE(us.memo_visibility, 'PRIVATE') AS memoVisibility,
      us.telegram_user_id AS telegramUserId
    FROM user_settings us
    INNER JOIN users u ON us.user_id = u.id
    WHERE us.telegram_user_id IN (${placeholders})
    LIMIT 1
  `);
  return stmt.bind(...uniqueCandidateIds).first();
}
__name(findUserByTelegramId, "findUserByTelegramId");
async function ensureMemoTags(db, memoId, tagNames, creatorId) {
  for (const tagName of tagNames) {
    await attachTagToMemo(db, memoId, tagName, creatorId);
  }
}
__name(ensureMemoTags, "ensureMemoTags");
async function createTelegramMemo(db, user, content) {
  const now = Math.floor(Date.now() / 1e3);
  const visibility = user.memoVisibility || "PRIVATE";
  const insertResult = await db.prepare(`
    INSERT INTO memos (creator_id, content, visibility, display_ts)
    VALUES (?, ?, ?, ?)
  `).bind(user.id, content, visibility, now).run();
  const memoId = insertResult.meta.last_row_id;
  const tagNames = extractTagNamesFromMemoContent(content);
  await ensureMemoTags(db, memoId, tagNames, user.id);
  return {
    memoId,
    createdTs: now,
    visibility,
    tagNames
  };
}
__name(createTelegramMemo, "createTelegramMemo");
async function getMemoNotificationData(db, memoId, userId) {
  const memoStmt = db.prepare(`
    SELECT
      m.id,
      m.content,
      m.visibility,
      m.creator_id as creatorId,
      m.created_ts as createdTs,
      u.username as creatorUsername,
      u.nickname as creatorName
    FROM memos m
    LEFT JOIN users u ON m.creator_id = u.id
    WHERE m.id = ? AND m.creator_id = ? AND m.row_status = 'NORMAL'
  `);
  const memo = await memoStmt.bind(memoId, userId).first();
  if (!memo) {
    return null;
  }
  const tagsStmt = db.prepare(`
    SELECT t.name
    FROM tags t
    INNER JOIN memo_tags mt ON mt.tag_id = t.id
    WHERE mt.memo_id = ?
    ORDER BY t.name ASC
  `);
  const resourcesStmt = db.prepare(`
    SELECT COUNT(*) as count
    FROM memo_resources
    WHERE memo_id = ?
  `);
  const [{ results: tags }, resourceCount] = await Promise.all([
    tagsStmt.bind(memoId).all(),
    resourcesStmt.bind(memoId).first()
  ]);
  return {
    ...memo,
    creatorName: memo.creatorName || memo.creatorUsername,
    tags: (tags || []).map((tag) => tag.name),
    resourceCount: resourceCount?.count || 0
  };
}
__name(getMemoNotificationData, "getMemoNotificationData");
async function updateMemoVisibility(db, memoId, userId, visibility) {
  if (!VALID_VISIBILITIES.includes(visibility)) {
    return false;
  }
  const result = await db.prepare(`
    UPDATE memos
    SET visibility = ?, updated_ts = ?
    WHERE id = ? AND creator_id = ? AND row_status = 'NORMAL'
  `).bind(
    visibility,
    Math.floor(Date.now() / 1e3),
    memoId,
    userId
  ).run();
  return result.changes > 0;
}
__name(updateMemoVisibility, "updateMemoVisibility");
async function handleCallbackQuery(db, telegramBotToken, instanceUrl, update) {
  const callbackQuery = update?.callback_query;
  if (!callbackQuery) {
    return null;
  }
  const callbackQueryId = callbackQuery.id;
  const chatId = String(callbackQuery.message?.chat?.id ?? "");
  const messageId = callbackQuery.message?.message_id;
  const fromId = String(callbackQuery.from?.id ?? "");
  const parsedAction = parseTelegramMemoVisibilityCallbackData(callbackQuery.data);
  if (!callbackQueryId || !chatId || !fromId || !messageId) {
    return jsonResponse({ ok: true, ignored: "invalid-callback-query" });
  }
  if (!parsedAction) {
    await answerTelegramCallback(telegramBotToken, callbackQueryId, "\u4E0D\u652F\u6301\u7684\u64CD\u4F5C");
    return jsonResponse({ ok: true, ignored: "unknown-callback-action" });
  }
  const boundUser = await findUserByTelegramId(db, [chatId, fromId]);
  if (!boundUser) {
    await answerTelegramCallback(telegramBotToken, callbackQueryId, "\u5F53\u524D Telegram \u8D26\u53F7\u672A\u7ED1\u5B9A Memos \u7528\u6237", true);
    return jsonResponse({ ok: true, ignored: "telegram user not bound" });
  }
  const currentMemo = await getMemoNotificationData(db, parsedAction.memoId, boundUser.id);
  if (!currentMemo) {
    await answerTelegramCallback(telegramBotToken, callbackQueryId, "Memo \u4E0D\u5B58\u5728\u6216\u4F60\u6CA1\u6709\u6743\u9650\u4FEE\u6539", true);
    return jsonResponse({ ok: true, ignored: "memo-not-found" });
  }
  if (currentMemo.visibility === parsedAction.visibility) {
    await answerTelegramCallback(
      telegramBotToken,
      callbackQueryId,
      `\u5F53\u524D\u5DF2\u662F${getTelegramVisibilityLabel(currentMemo.visibility)}`
    );
    return jsonResponse({
      ok: true,
      handled: "memo-visibility-unchanged",
      memoId: currentMemo.id,
      visibility: currentMemo.visibility
    });
  }
  const updated = await updateMemoVisibility(db, parsedAction.memoId, boundUser.id, parsedAction.visibility);
  if (!updated) {
    await answerTelegramCallback(telegramBotToken, callbackQueryId, "\u66F4\u65B0\u53EF\u89C1\u6027\u5931\u8D25", true);
    return jsonResponse({ ok: true, ignored: "memo-visibility-update-failed" });
  }
  const refreshedMemo = await getMemoNotificationData(db, parsedAction.memoId, boundUser.id);
  if (!refreshedMemo) {
    await answerTelegramCallback(telegramBotToken, callbackQueryId, "Memo \u5DF2\u4E0D\u5B58\u5728", true);
    return jsonResponse({ ok: true, ignored: "memo-not-found-after-update" });
  }
  try {
    await editTelegramMemoNotification(telegramBotToken, chatId, messageId, refreshedMemo, instanceUrl);
  } catch (error) {
    if (!String(error?.message || error).includes("message is not modified")) {
      throw error;
    }
  }
  await answerTelegramCallback(
    telegramBotToken,
    callbackQueryId,
    `\u5DF2\u5207\u6362\u4E3A${getTelegramVisibilityLabel(refreshedMemo.visibility)}`
  );
  return jsonResponse({
    ok: true,
    handled: "memo-visibility-updated",
    memoId: refreshedMemo.id,
    visibility: refreshedMemo.visibility
  });
}
__name(handleCallbackQuery, "handleCallbackQuery");
async function getTelegramSettings(db) {
  const { results: settings } = await db.prepare(`
    SELECT key, value
    FROM settings
    WHERE key IN ('telegram-bot-token', 'instance-url')
  `).all();
  const settingsMap = buildSettingsMap(settings);
  return {
    telegramBotToken: settingsMap["telegram-bot-token"],
    instanceUrl: settingsMap["instance-url"]?.replace(/\/+$/, "")
  };
}
__name(getTelegramSettings, "getTelegramSettings");
app13.get("/webhook/info", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const { telegramBotToken } = await getTelegramSettings(db);
    if (!telegramBotToken) {
      return errorResponse("Telegram bot token is not configured", 400);
    }
    const result = await callTelegramApi(telegramBotToken, "getWebhookInfo", {});
    return jsonResponse(result.result || {});
  } catch (error) {
    console.error("Error fetching Telegram webhook info:", error);
    return errorResponse(error.message || "Failed to fetch Telegram webhook info", 500);
  }
});
app13.post("/webhook/sync", async (c) => {
  const authError = await requireAdmin(c);
  if (authError)
    return authError;
  try {
    const db = c.env.DB;
    const body = await c.req.json().catch(() => ({}));
    const { telegramBotToken } = await getTelegramSettings(db);
    if (!telegramBotToken) {
      return errorResponse("Telegram bot token is not configured", 400);
    }
    const defaultWebhookUrl = `${new URL(c.req.url).origin}/api/v1/telegram/webhook`;
    const webhookUrl = (body.webhookUrl || defaultWebhookUrl).trim();
    const payload = {
      url: webhookUrl,
      drop_pending_updates: Boolean(body.dropPendingUpdates)
    };
    if (c.env.TELEGRAM_WEBHOOK_SECRET) {
      payload.secret_token = c.env.TELEGRAM_WEBHOOK_SECRET;
    }
    const setWebhookResult = await callTelegramApi(telegramBotToken, "setWebhook", payload);
    const webhookInfoResult = await callTelegramApi(telegramBotToken, "getWebhookInfo", {});
    return jsonResponse({
      message: setWebhookResult.description || "Webhook updated",
      webhookUrl,
      webhookInfo: webhookInfoResult.result || {}
    });
  } catch (error) {
    console.error("Error syncing Telegram webhook:", error);
    return errorResponse(error.message || "Failed to sync Telegram webhook", 500);
  }
});
app13.post("/webhook", async (c) => {
  try {
    const db = c.env.DB;
    const expectedSecret = c.env.TELEGRAM_WEBHOOK_SECRET;
    if (expectedSecret) {
      const providedSecret = c.req.header("X-Telegram-Bot-Api-Secret-Token");
      if (providedSecret !== expectedSecret) {
        return errorResponse("Forbidden", 403);
      }
    }
    let update;
    try {
      update = await c.req.json();
    } catch (error) {
      return errorResponse("Invalid Telegram update payload", 400);
    }
    const { telegramBotToken, instanceUrl } = await getTelegramSettings(db);
    if (!telegramBotToken) {
      console.warn("Telegram webhook called without telegram-bot-token configured");
      return jsonResponse({ ok: true, ignored: "telegram bot token not configured" });
    }
    const callbackResult = await handleCallbackQuery(db, telegramBotToken, instanceUrl, update);
    if (callbackResult) {
      return callbackResult;
    }
    const message = update?.message || update?.edited_message;
    if (!message) {
      return jsonResponse({ ok: true, ignored: "unsupported update type" });
    }
    const chatId = String(message.chat?.id ?? "");
    const fromId = String(message.from?.id ?? "");
    const chatType = message.chat?.type;
    const content = (message.text ?? message.caption ?? "").trim();
    const normalizedContent = content.toLowerCase();
    if (!chatId || !fromId) {
      return jsonResponse({ ok: true, ignored: "missing chat context" });
    }
    if (chatType !== "private") {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        "\u5F53\u524D\u53EA\u652F\u6301\u901A\u8FC7\u548C\u673A\u5668\u4EBA\u79C1\u804A\u53D1\u9001\u6587\u672C memo\u3002"
      );
      return jsonResponse({ ok: true, ignored: "non-private chat" });
    }
    const boundUser = await findUserByTelegramId(db, [chatId, fromId]);
    const isStartCommand = normalizedContent.startsWith("/start");
    const isIdCommand = normalizedContent === "/id" || normalizedContent.startsWith("/id@");
    if (isStartCommand || isIdCommand) {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        buildBindingMessage(chatId, fromId, boundUser)
      );
      return jsonResponse({ ok: true, handled: "binding-info" });
    }
    if (!boundUser) {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        buildBindingMessage(chatId, fromId, null)
      );
      return jsonResponse({ ok: true, ignored: "telegram user not bound" });
    }
    if (!content) {
      await sendTelegramText(
        telegramBotToken,
        chatId,
        "\u5F53\u524D\u53EA\u652F\u6301\u53D1\u9001\u6587\u672C\u6D88\u606F\u521B\u5EFA memo\u3002"
      );
      return jsonResponse({ ok: true, ignored: "empty message" });
    }
    const memo = await createTelegramMemo(db, boundUser, content);
    const notificationMemoData = {
      id: memo.memoId,
      content,
      visibility: memo.visibility,
      creatorId: boundUser.id,
      creatorUsername: boundUser.username,
      creatorName: boundUser.nickname || boundUser.username,
      createdTs: memo.createdTs,
      tags: memo.tagNames,
      resourceCount: 0
    };
    c.executionCtx.waitUntil(
      sendAllNotifications(db, notificationMemoData, {
        skipTelegram: true
      }).catch((error) => {
        console.error("Error sending notifications for Telegram memo:", error);
      })
    );
    await sendTelegramNotification(telegramBotToken, chatId, notificationMemoData, instanceUrl);
    return jsonResponse({
      ok: true,
      memoId: memo.memoId
    });
  } catch (error) {
    console.error("Error handling Telegram webhook:", error);
    return errorResponse("Failed to handle Telegram webhook", 500);
  }
});
var telegram_default = app13;

// src/index.js
var app14 = new Hono2();
app14.use("/*", cors({
  origin: (origin) => {
    return origin || true;
  },
  allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "Authorization", "X-Token"],
  exposeHeaders: ["Content-Length", "Content-Type", "X-Token"],
  maxAge: 86400,
  // 24小时
  credentials: true
  // 支持携带凭证（cookies, authorization headers）
}));
app14.route("/api/v1/auth", auth_default);
app14.route("/api/v1/memo", memos_default);
app14.route("/api/v1/memo", memoRelations_default);
app14.route("/api/v1/tag", tags_default);
app14.route("/api/v1/user", users_default);
app14.route("/api/v1/user", accessTokens_default);
app14.route("/api/v1/user/setting", userSettings_default);
app14.route("/api/v1/resource", resources_default);
app14.route("/api/v1/settings", settings_default);
app14.route("/api/v1/system/setting", settings_default);
app14.route("/api/v1/webhook", webhooks_default);
app14.route("/api/v1/idp", identityProviders_default);
app14.route("/api/v1/telegram", telegram_default);
app14.get("/api/v1/storage", async (c) => {
  return c.json([]);
});
app14.route("/api/v1/rss", rss_default);
app14.get("/api/v1/ping", (c) => {
  return c.json({ status: "ok" });
});
app14.post("/api/v1/system/vacuum", async (c) => {
  try {
    const db = c.env.DB;
    try {
      await db.prepare("VACUUM").run();
      return c.json({
        status: "ok",
        message: "Database vacuumed successfully"
      });
    } catch (vacuumError) {
      console.log("VACUUM command not supported on Cloudflare D1:", vacuumError);
      return c.json({
        status: "ok",
        message: "Database optimization is handled automatically by Cloudflare D1"
      });
    }
  } catch (error) {
    console.error("Error in vacuum endpoint:", error);
    return c.json({
      status: "error",
      message: "Failed to vacuum database"
    }, 500);
  }
});
app14.get("/api/v1/status", async (c) => {
  try {
    const db = c.env.DB;
    const userCountStmt = db.prepare("SELECT COUNT(*) as count FROM users");
    const memoCountStmt = db.prepare('SELECT COUNT(*) as count FROM memos WHERE row_status = "NORMAL"');
    const resourceCountStmt = db.prepare("SELECT COUNT(*) as count FROM resources");
    const userCount = await userCountStmt.first();
    const memoCount = await memoCountStmt.first();
    const resourceCount = await resourceCountStmt.first();
    const hostStmt = db.prepare(`
      SELECT id, username, nickname, email, role
      FROM users
      WHERE role = 'host' OR is_admin = 1
      ORDER BY id ASC
      LIMIT 1
    `);
    const hostUser = await hostStmt.first();
    const settingsStmt = db.prepare("SELECT key, value FROM settings");
    const { results: settingsResults } = await settingsStmt.all();
    const settings = {};
    settingsResults.forEach((setting) => {
      settings[setting.key] = setting.value;
    });
    const parseSettingValue = /* @__PURE__ */ __name((value) => {
      if (!value)
        return "";
      try {
        return JSON.parse(value);
      } catch (e) {
        return value;
      }
    }, "parseSettingValue");
    const response = {
      status: "ok",
      version: "v1",
      timestamp: Date.now(),
      profile: {
        mode: "prod",
        version: "1.0.0"
      },
      dbSize: 0,
      allowSignUp: settings.allow_registration === "true",
      disablePasswordLogin: settings["disable-password-login"] === "true",
      disablePublicMemos: settings["disable-public-memos"] === "true",
      maxUploadSizeMiB: parseInt(parseSettingValue(settings["max-upload-size-mib"])) || 50,
      autoBackupInterval: parseInt(parseSettingValue(settings["auto-backup-interval"])) || 0,
      additionalStyle: parseSettingValue(settings["additional-style"]) || "",
      additionalScript: parseSettingValue(settings["additional-script"]) || "",
      memoDisplayWithUpdatedTs: settings["memo-display-with-updated-ts"] === "true",
      timezone: c.env.TIMEZONE || "",
      // 从环境变量读取时区配置
      customizedProfile: (() => {
        const customizedProfileStr = settings["customized-profile"];
        if (customizedProfileStr) {
          try {
            const parsed = JSON.parse(customizedProfileStr);
            return {
              name: parsed.name || settings.site_title || "Memos",
              logoUrl: parsed.logoUrl || "/logo.png",
              description: parsed.description || "",
              locale: parsed.locale || "zh-Hans",
              appearance: parsed.appearance || "system",
              externalUrl: parsed.externalUrl || ""
            };
          } catch (e) {
            console.error("Failed to parse customized-profile:", e);
          }
        }
        return {
          name: settings.site_title || "Memos",
          logoUrl: "/logo.png",
          description: "",
          locale: "zh-Hans",
          appearance: "system",
          externalUrl: ""
        };
      })(),
      stats: {
        users: userCount.count,
        memos: memoCount.count,
        resources: resourceCount.count
      },
      settings: {
        siteTitle: settings.site_title || "Memos",
        allowRegistration: settings.allow_registration === "true"
      },
      features: {
        authentication: true,
        memoRelations: true,
        tags: true,
        resources: true,
        rss: true
      }
    };
    if (hostUser) {
      response.host = {
        id: hostUser.id,
        name: `users/${hostUser.username}`,
        username: hostUser.username,
        nickname: hostUser.nickname,
        email: hostUser.email || "",
        role: hostUser.role
      };
    }
    return c.json(response);
  } catch (error) {
    console.error("Error fetching system status:", error);
    return c.json({
      status: "error",
      message: "Failed to fetch system status",
      timestamp: Date.now()
    }, 500);
  }
});
app14.get("/api/health", (c) => {
  return c.json({
    status: "ok",
    timestamp: Date.now(),
    version: "v1"
  });
});
app14.get("/rss.xml", async (c) => {
  return c.redirect("/api/v1/rss/rss.xml", 301);
});
app14.get("/u/:userId/rss.xml", async (c) => {
  const userId = c.req.param("userId");
  return c.redirect(`/api/v1/rss/u/${userId}/rss.xml`, 301);
});
app14.get("/o/r/:id/:filename", async (c) => {
  try {
    const db = c.env.DB;
    const bucket = c.env.BUCKET;
    const id = c.req.param("id");
    const stmt = db.prepare(`
      SELECT id, filename, filepath, type, size
      FROM resources
      WHERE id = ?
    `);
    const resource = await stmt.bind(id).first();
    if (!resource) {
      return c.text("Resource not found", 404);
    }
    let objectKey = resource.filepath;
    if (objectKey.startsWith("http")) {
      const url = new URL(objectKey);
      objectKey = url.pathname.substring(1);
    }
    const object = await bucket.get(objectKey);
    if (!object) {
      return c.text("File not found in storage", 404);
    }
    return new Response(object.body, {
      headers: {
        "Content-Type": resource.type || "application/octet-stream",
        "Content-Length": resource.size?.toString() || "",
        "Content-Disposition": `inline; filename="${encodeURIComponent(resource.filename)}"`,
        "Cache-Control": "public, max-age=31536000"
      }
    });
  } catch (error) {
    console.error("Error proxying resource:", error);
    return c.text("Error accessing resource", 500);
  }
});
app14.get("/:filename", async (c) => {
  const filename = c.req.param("filename");
  if (filename && filename.match(/^\d+_\d+\.\w+$/)) {
    try {
      const bucket = c.env.BUCKET;
      const object = await bucket.get(filename);
      if (!object) {
        return c.text("File not found", 404);
      }
      const contentType = object.httpMetadata?.contentType || "application/octet-stream";
      return new Response(object.body, {
        headers: {
          "Content-Type": contentType,
          "Cache-Control": "public, max-age=31536000"
        }
      });
    } catch (error) {
      console.error("Error serving file:", error);
      return c.text("Error serving file", 500);
    }
  }
  return c.text("Not Found", 404);
});
app14.notFound((c) => {
  return c.text("Not Found", 404);
});
app14.onError((err, c) => {
  console.error("Worker error:", err);
  return c.json({
    error: "Internal Server Error",
    message: err.message
  }, 500);
});
var src_default = app14;
export {
  src_default as default
};
//# sourceMappingURL=index.js.map
