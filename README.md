# 部署文档

本项目基于 **Cloudflare** 全家桶构建：

- **后端**：Cloudflare Workers（Hono 框架）
- **数据库**：Cloudflare D1（SQLite）
- **对象存储**：Cloudflare R2
- **前端**：Cloudflare Pages（React + Vite）

---

## 目录

1. [前置条件](#1-前置条件)
2. [首次手动部署（初始化）](#2-首次手动部署初始化)
   - 2.1 [创建 D1 数据库](#21-创建-d1-数据库)
   - 2.2 [创建 R2 存储桶](#22-创建-r2-存储桶)
   - 2.3 [配置 wrangler.toml](#23-配置-wranglertoml)
   - 2.4 [初始化数据库表结构](#24-初始化数据库表结构)
   - 2.5 [部署后端 Worker](#25-部署后端-worker)
   - 2.6 [部署前端到 Pages](#26-部署前端到-pages)
   - 2.7 [配置 Service Binding](#27-配置-service-binding)
3. [GitHub Actions 自动部署](#3-github-actions-自动部署)
   - 3.1 [创建 Cloudflare API Token](#31-创建-cloudflare-api-token)
   - 3.2 [配置 GitHub Secrets](#32-配置-github-secrets)
   - 3.3 [触发自动部署](#33-触发自动部署)
4. [环境变量说明](#4-环境变量说明)
5. [常见问题](#5-常见问题)

---

## 1. 前置条件

| 工具 | 版本要求 | 说明 |
|------|----------|------|
| Node.js | >= 18 | 建议使用 20 LTS |
| npm | >= 9 | 随 Node.js 安装 |
| Wrangler CLI | >= 3 | Cloudflare 官方命令行工具 |
| Cloudflare 账号 | - | 需开通 Workers、D1、R2、Pages |

安装 Wrangler：

```bash
npm install -g wrangler
wrangler login
```

---

## 2. 首次手动部署（初始化）

> 首次部署必须手动完成，主要是创建云端资源并获取对应 ID 填入配置。

### 2.1 创建 D1 数据库

```bash
cd backend
npm run db:create
```

输出示例：

```
✅ Successfully created DB 'memos_db'
{
  "uuid": "e03f026e-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  ...
}
```

复制输出中的 `uuid`，填入 `backend/wrangler.toml`：

```toml
[[d1_databases]]
binding = "DB"
database_name = "memos_db"
database_id = "<你的 uuid>"
```

### 2.2 创建 R2 存储桶

```bash
wrangler r2 bucket create memos
```

> R2 存储桶名称须全局唯一，如 `memos` 已被占用可改为 `memos-yourname`，同步修改 `wrangler.toml` 中的 `bucket_name`。

### 2.3 配置 wrangler.toml

`backend/wrangler.toml` 完整示例：

```toml
name = "memos-api"
main = "src/index.js"
compatibility_date = "2024-01-15"
compatibility_flags = ["nodejs_compat"]

[vars]
TIMEZONE = "Asia/Shanghai"

[[d1_databases]]
binding = "DB"
database_name = "memos_db"
database_id = "<你的 D1 数据库 ID>"

[[r2_buckets]]
binding = "BUCKET"
bucket_name = "memos"
```

### 2.4 初始化数据库表结构

```bash
cd backend
npm run db:init
```

该命令执行 `schema.sql`，在远程 D1 数据库中创建所有表。

> 本地开发时使用 `npm run db:local` 初始化本地数据库。

### 2.5 部署后端 Worker

```bash
cd backend
npm run deploy
```

部署成功后，Wrangler 会输出 Worker 的访问地址，例如：

```
https://memos-api.<your-subdomain>.workers.dev
```

记录该地址，后续配置前端 fallback URL 时使用。

### 2.6 部署前端到 Pages

**方式一：通过 Wrangler CLI（推荐）**

```bash
cd frontend
npm ci
npm run build
wrangler pages deploy dist --project-name=memos-frontend
```

首次执行时 Wrangler 会自动创建 Pages 项目。

**方式二：通过 Cloudflare Dashboard**

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 **Workers & Pages → Create → Pages → Connect to Git**
3. 选择本仓库，设置构建配置：
   - **Framework preset**：None
   - **Build command**：`cd frontend && npm ci && npm run build`
   - **Build output directory**：`frontend/dist`
   - **Root directory**：`/`

### 2.7 配置 Service Binding

Service Binding 让前端 Pages 直接内部调用后端 Worker，无需跨域请求，性能更好。

1. 进入 Cloudflare Dashboard → **Workers & Pages** → 选择前端 Pages 项目
2. 点击 **Settings → Functions**
3. 在 **Service bindings** 中添加：
   - **Variable name**：`BACKEND`
   - **Service**：选择你的 Worker（`memos-api`）
   - **Environment**：`production`
4. 点击 **Save**

> 配置 Service Binding 后，`frontend/functions/_middleware.js` 会自动使用内部调用，无需配置 CORS。

---

## 3. GitHub Actions 自动部署

每次推送到 `main` 分支时，工作流会自动：
1. 部署后端 Worker
2. 构建前端并部署到 Cloudflare Pages

### 3.1 创建 Cloudflare API Token

1. 进入 [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. 点击 **Create Token → Custom Token**
3. 配置权限：

| 权限类型 | 资源 | 操作 |
|----------|------|------|
| Account | Cloudflare Pages | Edit |
| Account | Workers Scripts | Edit |
| Account | Workers D1 | Edit |
| Account | Workers R2 Storage | Edit |
| Zone | Workers Routes | Edit（可选，如需自定义域名） |

4. 点击 **Continue to summary → Create Token**，复制 Token（只显示一次）

### 3.2 配置 GitHub Secrets

进入 GitHub 仓库 → **Settings → Secrets and variables → Actions → New repository secret**，添加以下 3 个 Secret：

| Secret 名称 | 说明 | 获取方式 |
|-------------|------|----------|
| `CLOUDFLARE_API_TOKEN` | 上一步创建的 API Token | 见 3.1 |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare 账号 ID | Dashboard 右侧边栏 → Account ID |
| `CF_PAGES_PROJECT_NAME` | Pages 项目名称 | 如 `memos-frontend` |

### 3.3 触发自动部署

**自动触发**：推送代码到 `main` 分支即自动触发。

```bash
git add .
git commit -m "your changes"
git push origin main
```

**手动触发**：进入 GitHub 仓库 → **Actions → Deploy to Cloudflare → Run workflow**。

---

## 4. 环境变量说明

### 后端（wrangler.toml `[vars]`）

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `TIMEZONE` | `Asia/Shanghai` | 服务端时区，影响 RSS 时间显示 |

### 前端（无需额外环境变量）

前端通过 Service Binding 或相对路径调用后端 API，无需配置 API 地址。

如需修改 fallback 后端地址（未配置 Service Binding 时），编辑：

```js
// frontend/functions/_middleware.js 第 43 行
const backendUrl = 'https://memos-api.your-domain.workers.dev' + url.pathname + url.search;
```

---

## 5. 常见问题

### Q: 部署后上传文件报 500 错误

**原因**：R2 bucket 未绑定或 bucket 名称不匹配。

**排查**：
1. 确认 `wrangler.toml` 中 `bucket_name` 与 Cloudflare Dashboard 中 R2 bucket 名称一致
2. 重新执行 `npm run deploy`

### Q: 前端访问 API 报 CORS 错误

**原因**：未配置 Service Binding，且 fallback URL 指向错误地址。

**解决**：按照 [2.7 节](#27-配置-service-binding) 配置 Service Binding，或修改 `_middleware.js` 中的 fallback URL。

### Q: GitHub Actions 部署失败，提示 `authentication error`

**原因**：API Token 权限不足或 Secret 配置错误。

**排查**：
1. 检查 GitHub Secrets 中三个变量是否正确填写（无多余空格）
2. 检查 API Token 权限是否包含 Pages Edit 和 Workers Scripts Edit

### Q: 数据库迁移 / 重置

> ⚠️ 以下操作会清空数据，请先备份。

```bash
# 仅在需要重建表结构时执行
cd backend
wrangler d1 execute memos_db --command="DROP TABLE IF EXISTS memos" --remote
npm run db:init
```

### Q: 本地开发

```bash
# 终端 1：启动后端（本地 D1 + R2 模拟）
cd backend
npm run dev

# 终端 2：启动前端（代理到本地后端 :8787）
cd frontend
npm install
npm run dev
```

前端开发服务器运行在 `http://localhost:5173`，API 请求自动代理到 `http://127.0.0.1:8787`。
