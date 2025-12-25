# Cloudflare-Memos 后端 API

这是 Cloudflare-Memos 的后端 API 服务，部署在 Cloudflare Workers 上。

## 技术栈

- **运行时**：Cloudflare Workers
- **框架**：Hono.js
- **数据库**：Cloudflare D1 (SQLite)
- **存储**：Cloudflare R2 (S3 兼容)
- **认证**：Token-based + PBKDF2 密码哈希

## 本地开发

### 1. 安装依赖

```bash
npm install
```

### 2. 初始化本地数据库

```bash
# 创建本地 D1 数据库
npm run db:local -- --file=schema.sql

# 或者使用完整命令
wrangler d1 execute memos_db --local --file=schema.sql
```

### 3. 启动开发服务器

```bash
npm run dev
```

后端 API 将运行在 `http://localhost:8787`

### 4. 测试 API

访问健康检查端点：
```bash
curl http://localhost:8787/api/health
```

预期响应：
```json
{
  "status": "ok",
  "timestamp": 1703174400000,
  "version": "v1"
}
```

## API 端点

### 基础路径
- 本地开发: `http://localhost:8787/api/v1`
- 生产环境: `https://your-api-domain/api/v1`

### 用户相关
- `POST /api/v1/user` - 注册用户
- `POST /api/v1/user/login` - 用户登录
- `POST /api/v1/user/logout` - 用户登出
- `GET /api/v1/user` - 获取用户列表（需认证）
- `GET /api/v1/user/:id` - 获取用户信息
- `PUT /api/v1/user/:id` - 更新用户信息（需认证）
- `PUT /api/v1/user/:id/password` - 修改密码（需认证）
- `DELETE /api/v1/user/:id` - 删除用户（需管理员）

### 备忘录相关
- `GET /api/v1/memo` - 获取备忘录列表
- `GET /api/v1/memo/:id` - 获取备忘录详情
- `POST /api/v1/memo` - 创建备忘录（需认证）
- `PUT /api/v1/memo/:id` - 更新备忘录（需认证）
- `PATCH /api/v1/memo/:id` - 部分更新备忘录（需认证）
- `DELETE /api/v1/memo/:id` - 删除备忘录（需认证）
- `GET /api/v1/memo/search` - 搜索备忘录
- `GET /api/v1/memo/stats` - 获取统计数据（需认证）
- `GET /api/v1/memo/stats/heatmap` - 获取热力图数据（需认证）

### 资源相关
- `GET /api/v1/resource` - 获取资源列表（需认证）
- `GET /api/v1/resource/:id` - 获取资源元数据
- `GET /api/v1/resource/:id/file` - 下载资源文件
- `POST /api/v1/resource` - 上传资源（需认证）
- `DELETE /api/v1/resource/:id` - 删除资源（需认证）

### 设置相关
- `GET /api/v1/settings/public` - 获取公开设置
- `GET /api/v1/settings` - 获取所有设置（需管理员）
- `PUT /api/v1/settings/:key` - 更新设置（需管理员）

### RSS
- `GET /api/v1/rss` - 获取 RSS 订阅源
- `GET /api/v1/rss/user/:id` - 获取用户的 RSS 订阅源

### 其他
- `GET /api/health` - 健康检查
- `GET /favicon.ico` - 网站图标
- `GET /:filename` - 直接访问上传的文件（格式：用户ID_时间戳.扩展名）

## 认证

API 支持三种认证方式：

### 1. Authorization Header（推荐）
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8787/api/v1/memo
```

### 2. X-Token Header
```bash
curl -H "X-Token: YOUR_TOKEN" \
  http://localhost:8787/api/v1/memo
```

### 3. Query Parameter
```bash
curl "http://localhost:8787/api/v1/memo?token=YOUR_TOKEN"
```

## 响应格式

### 成功响应
```json
{
  "data": { /* 返回的数据 */ }
}
```

或

```json
{
  "data": { /* 返回的数据 */ },
  "message": "操作成功"
}
```

### 错误响应
```json
{
  "error": "错误信息",
  "code": "ERROR_CODE"
}
```

## CORS 配置

后端已配置 CORS 支持，允许以下来源：
- `http://localhost:5173` (Vite 默认端口)
- `http://localhost:3000` (备用端口)
- 环境变量 `ALLOWED_ORIGINS` 中配置的域名

### 配置生产环境 CORS

在 `wrangler.toml` 中设置：

```toml
[env.production.vars]
ALLOWED_ORIGINS = "https://your-frontend.pages.dev,https://your-domain.com"
```

## 部署

### 部署到生产环境

```bash
# 1. 确保已登录 Cloudflare
wrangler login

# 2. 部署
npm run deploy
```

### 初始化生产数据库

```bash
# 执行数据库初始化脚本
wrangler d1 execute memos_db --file=schema.sql
```

### 部署后配置

1. 记录部署后的 API 地址（例如：`https://memos-api.your-username.workers.dev`）
2. 在前端项目中配置此 API 地址
3. 更新 `wrangler.toml` 中的 `ALLOWED_ORIGINS`，添加前端域名
4. 重新部署：`npm run deploy`

## 项目结构

```
backend/
├── src/
│   ├── index.js              # 主入口，路由配置
│   ├── handlers/             # API 处理器
│   │   ├── memos.js         # 备忘录 API
│   │   ├── users.js         # 用户 API
│   │   ├── resources.js     # 资源 API
│   │   ├── settings.js      # 设置 API
│   │   └── rss.js           # RSS API
│   ├── utils/               # 工具函数
│   │   ├── auth.js          # 认证相关
│   │   ├── cors.js          # CORS 配置
│   │   └── gravatar.js      # Gravatar 头像
│   └── favicon.ico          # 网站图标
├── schema.sql               # 数据库 Schema
├── wrangler.toml            # Cloudflare Workers 配置
├── package.json
└── README.md
```

## 数据库管理

### 查看数据库
```bash
# 本地
wrangler d1 execute memos_db --local --command="SELECT * FROM users"

# 生产
wrangler d1 execute memos_db --command="SELECT * FROM users"
```

### 备份数据库
```bash
# 导出生产数据库
wrangler d1 export memos_db --output=backup.sql
```

### 恢复数据库
```bash
# 恢复到生产数据库
wrangler d1 execute memos_db --file=backup.sql
```

## 常见问题

### 1. CORS 错误

确保在 `wrangler.toml` 中正确配置了 `ALLOWED_ORIGINS`：

```toml
[vars]
ALLOWED_ORIGINS = "http://localhost:5173"
```

### 2. 数据库连接失败

检查 `wrangler.toml` 中的数据库配置是否正确，确保 `database_id` 匹配。

### 3. R2 文件上传失败

确保在 Cloudflare Dashboard 中创建了名为 `memos` 的 R2 存储桶。

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `GRAVATAR_CDN` | Gravatar CDN 地址 | `https://gravatar.loli.net` |
| `ALLOWED_ORIGINS` | 允许的 CORS 来源（逗号分隔） | `""` |
| `ENVIRONMENT` | 运行环境 | `development` |

## 开发建议

1. 使用 `wrangler tail` 查看实时日志：
   ```bash
   npm run tail
   ```

2. 测试 API 时使用 Postman、Insomnia 或 curl

3. 修改代码后，Wrangler 会自动重载

## 相关链接

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [Hono.js 文档](https://hono.dev/)
- [Cloudflare D1 文档](https://developers.cloudflare.com/d1/)
- [Cloudflare R2 文档](https://developers.cloudflare.com/r2/)
