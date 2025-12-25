-- 添加 row_status 字段到 users 表
-- 迁移日期: 2024-12-25

-- 为 users 表添加 row_status 字段，默认值为 0 (NORMAL)
ALTER TABLE users ADD COLUMN row_status INTEGER NOT NULL DEFAULT 0;

-- 注释：
-- row_status 值说明：
-- 0 = NORMAL (正常状态)
-- 1 = ARCHIVED (已归档)
