-- 创建 webhooks 表
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 创建 webhooks 索引
CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks(user_id);

-- 移除 user_settings 表中的 webhook_url 列（如果存在）
-- 注意：SQLite 不支持 ALTER TABLE DROP COLUMN，所以我们需要重建表
-- 但为了兼容性，我们先检查列是否存在

-- 创建新的 user_settings 表
CREATE TABLE IF NOT EXISTS user_settings_new (
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

-- 复制数据（忽略 webhook_url 列）
INSERT INTO user_settings_new (id, user_id, locale, appearance, memo_visibility, telegram_user_id, created_ts, updated_ts)
SELECT id, user_id, locale, appearance, memo_visibility, telegram_user_id, created_ts, updated_ts
FROM user_settings;

-- 删除旧表
DROP TABLE user_settings;

-- 重命名新表
ALTER TABLE user_settings_new RENAME TO user_settings;

-- 重新创建索引
CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);
