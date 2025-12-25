-- 用户设置表迁移
CREATE TABLE IF NOT EXISTS user_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    locale TEXT DEFAULT 'en',
    appearance TEXT DEFAULT 'auto',
    memo_visibility TEXT DEFAULT 'PRIVATE',
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 添加用户设置索引
CREATE INDEX IF NOT EXISTS idx_user_settings_user_id ON user_settings(user_id);
