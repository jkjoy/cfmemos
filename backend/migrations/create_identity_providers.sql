-- 身份提供商表（用于SSO登录）
CREATE TABLE IF NOT EXISTS identity_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    identifier_filter TEXT DEFAULT '',
    config TEXT NOT NULL,
    created_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
