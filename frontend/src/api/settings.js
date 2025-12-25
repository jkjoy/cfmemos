import apiClient from './client';

/**
 * 设置 API
 */
export const settingsAPI = {
  /**
   * 获取公开设置
   */
  getPublic: () => {
    return apiClient.get('/settings/public');
  },

  /**
   * 获取所有设置（需要管理员权限）
   */
  getAll: () => {
    return apiClient.get('/settings');
  },

  /**
   * 更新设置（需要管理员权限）
   * @param {string} key - 设置键
   * @param {any} value - 设置值
   */
  update: (key, value) => {
    return apiClient.put(`/settings/${key}`, { value });
  }
};

/**
 * RSS API
 */
export const rssAPI = {
  /**
   * 获取全局 RSS 订阅源 URL
   */
  getGlobalUrl: () => {
    return `${apiClient.defaults.baseURL}/rss`;
  },

  /**
   * 获取用户 RSS 订阅源 URL
   * @param {string|number} userId - 用户 ID
   */
  getUserUrl: (userId) => {
    return `${apiClient.defaults.baseURL}/rss/user/${userId}`;
  }
};
