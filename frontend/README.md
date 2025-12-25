# Cloudflare-Memos 前端应用

这是 Cloudflare-Memos 的前端应用，基于 React + Vite 构建，实现前后端分离架构。

## 技术栈

- **框架**：React 18
- **构建工具**：Vite
- **路由**：React Router v6
- **数据请求**：TanStack Query (React Query)
- **状态管理**：Zustand
- **HTTP 客户端**：Axios
- **Markdown 渲染**：react-markdown

## 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 启动开发服务器

```bash
npm run dev
```

前端应用将运行在 `http://localhost:5173`

**注意**：确保后端 API 服务也在运行（`http://localhost:8787`）

### 3. 构建生产版本

```bash
npm run build
```

构建产物将输出到 `dist/` 目录

## 项目结构

```
frontend/
├── src/
│   ├── api/            # API 请求封装
│   ├── store/          # Zustand 状态管理
│   ├── routes/         # 页面组件
│   ├── components/     # 可复用组件
│   ├── App.jsx         # 主应用组件
│   └── main.jsx        # 入口文件
├── vite.config.js      # Vite 配置
└── package.json
```

## 主要功能

✅ 用户认证（登录/注册/登出）
✅ 认证状态持久化
✅ API 请求封装和拦截器
✅ 路由保护
✅ 备忘录列表展示

## 开发指南

详细文档请查看项目根目录的 `REFACTOR_PLAN.md`

## 部署

### 部署到 Cloudflare Pages

```bash
npm run build
npx wrangler pages deploy dist --project-name=memos-frontend
```

### 环境变量

- `VITE_API_URL`: 后端 API 地址（生产环境必填）

## 相关链接

- [后端 API 文档](../backend/README.md)
- [重构方案](../REFACTOR_PLAN.md)
