-- 为 tags 表添加 creator_id 字段
-- 这个迁移修复了 tags 表缺少 creator_id 的问题

-- 1. 添加 creator_id 字段（允许 NULL，因为可能有旧数据）
ALTER TABLE tags ADD COLUMN creator_id INTEGER;

-- 2. 为现有的标签设置默认 creator（第一个管理员用户）
UPDATE tags
SET creator_id = (SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1)
WHERE creator_id IS NULL;

-- 3. 创建索引以优化查询性能
CREATE INDEX IF NOT EXISTS idx_tags_creator_id ON tags(creator_id);
