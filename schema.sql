-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    nickname TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    avatar_url TEXT,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    is_admin INTEGER NOT NULL DEFAULT 0,
    role TEXT DEFAULT 'user',
    row_status INTEGER NOT NULL DEFAULT 0
);

-- 备忘录表
CREATE TABLE IF NOT EXISTS memos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'PUBLIC',
    row_status TEXT NOT NULL DEFAULT 'NORMAL',
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    display_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    pinned INTEGER NOT NULL DEFAULT 0,
    parent_id INTEGER,
    FOREIGN KEY (creator_id) REFERENCES users(id),
    FOREIGN KEY (parent_id) REFERENCES memos(id)
);

-- 资源表
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    size INTEGER,
    type TEXT,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (creator_id) REFERENCES users(id)
);

-- 备忘录与资源关联表
CREATE TABLE IF NOT EXISTS memo_resources (
    memo_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    PRIMARY KEY (memo_id, resource_id),
    FOREIGN KEY (memo_id) REFERENCES memos(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE
);

-- 标签表
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    creator_id INTEGER NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(name, creator_id),
    FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 备忘录与标签关联表
CREATE TABLE IF NOT EXISTS memo_tags (
    memo_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY (memo_id, tag_id),
    FOREIGN KEY (memo_id) REFERENCES memos(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- 备忘录关系表（评论、引用等）
CREATE TABLE IF NOT EXISTS memo_relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memo_id INTEGER NOT NULL,
    related_memo_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('REFERENCE', 'COMMENT')),
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (memo_id) REFERENCES memos(id) ON DELETE CASCADE,
    FOREIGN KEY (related_memo_id) REFERENCES memos(id) ON DELETE CASCADE,
    UNIQUE(memo_id, related_memo_id, type)
);

-- API Token表
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_ts INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 用户设置表
CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    locale TEXT DEFAULT 'en',
    appearance TEXT DEFAULT 'auto',
    memo_visibility TEXT DEFAULT 'PRIVATE',
    telegram_user_id TEXT DEFAULT '',
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- SSO 身份提供者表
CREATE TABLE IF NOT EXISTS identity_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    identifier_filter TEXT DEFAULT '',
    config TEXT NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Webhook 表
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 会话表（用于用户登录会话管理）
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_ts INTEGER NOT NULL,
    last_active_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 系统设置表
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT,
    description TEXT,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_memos_creator_id ON memos(creator_id);
CREATE INDEX IF NOT EXISTS idx_memos_created_ts ON memos(created_ts);
CREATE INDEX IF NOT EXISTS idx_memos_visibility ON memos(visibility);
-- 常用排序字段 display_ts 也加索引
CREATE INDEX IF NOT EXISTS idx_memos_display_ts ON memos(display_ts);
-- 添加组合索引优化搜索查询性能
CREATE INDEX IF NOT EXISTS idx_memos_status_visibility ON memos(row_status, visibility);
CREATE INDEX IF NOT EXISTS idx_memos_creator_status ON memos(creator_id, row_status);
CREATE INDEX IF NOT EXISTS idx_memos_display_status ON memos(display_ts, row_status);
CREATE INDEX IF NOT EXISTS idx_resources_creator_id ON resources(creator_id);
-- 添加 memo_resources 关联表索引以优化 JOIN 查询
CREATE INDEX IF NOT EXISTS idx_memo_resources_memo_id ON memo_resources(memo_id);
CREATE INDEX IF NOT EXISTS idx_memo_resources_resource_id ON memo_resources(resource_id);
-- 添加标签索引
CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
CREATE INDEX IF NOT EXISTS idx_tags_creator_id ON tags(creator_id);
CREATE INDEX IF NOT EXISTS idx_memo_tags_memo_id ON memo_tags(memo_id);
CREATE INDEX IF NOT EXISTS idx_memo_tags_tag_id ON memo_tags(tag_id);
-- 添加 memo_relations 索引
CREATE INDEX IF NOT EXISTS idx_memo_relations_memo_id ON memo_relations(memo_id);
CREATE INDEX IF NOT EXISTS idx_memo_relations_related_memo_id ON memo_relations(related_memo_id);
CREATE INDEX IF NOT EXISTS idx_memo_relations_type ON memo_relations(type);
-- 添加 API tokens 索引
CREATE INDEX IF NOT EXISTS idx_api_tokens_token ON api_tokens(token);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
-- 添加用户设置索引
CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);
-- 添加 webhooks 索引
CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks(user_id);
-- 添加会话索引
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_ts ON sessions(expires_ts);

-- 插入系统默认设置
INSERT OR IGNORE INTO settings (key, value, description) VALUES
    ('site_title', 'Memos', '网站标题'),
    ('site_avatar', '', '网站头像URL'),
    ('allow_registration', 'true', '是否允许注册 (true/false)');

-- 插入默认管理员用户（第一个注册用户将自动成为管理员）
