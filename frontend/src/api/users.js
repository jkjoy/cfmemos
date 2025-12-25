import apiClient from './client';

/**
 * 用户 API
 */
export const userAPI = {
  /**
   * 用户登录
   * @param {Object} credentials - 登录凭证
   * @param {string} credentials.username - 用户名
   * @param {string} credentials.password - 密码
   */
  login: (credentials) => {
    return apiClient.post('/user/login', credentials);
  },

  /**
   * 用户注册
   * @param {Object} data - 注册数据
   * @param {string} data.username - 用户名
   * @param {string} data.password - 密码
   * @param {string} data.email - 邮箱（可选）
   * @param {string} data.nickname - 昵称（可选）
   */
  register: (data) => {
    return apiClient.post('/user', data);
  },

  /**
   * 用户登出
   */
  logout: () => {
    return apiClient.post('/user/logout');
  },

  /**
   * 获取用户列表
   * @param {Object} params - 查询参数
   */
  list: (params = {}) => {
    return apiClient.get('/user', { params });
  },

  /**
   * 获取用户信息
   * @param {string|number} id - 用户 ID，传 'me' 获取当前用户
   */
  get: (id = 'me') => {
    return apiClient.get(`/user/${id}`);
  },

  /**
   * 更新用户信息
   * @param {string|number} id - 用户 ID
   * @param {Object} data - 更新数据
   */
  update: (id, data) => {
    return apiClient.put(`/user/${id}`, data);
  },

  /**
   * 修改密码
   * @param {string|number} id - 用户 ID
   * @param {Object} data - 密码数据
   * @param {string} data.oldPassword - 旧密码
   * @param {string} data.newPassword - 新密码
   */
  changePassword: (id, data) => {
    return apiClient.put(`/user/${id}/password`, data);
  },

  /**
   * 删除用户
   * @param {string|number} id - 用户 ID
   */
  delete: (id) => {
    return apiClient.delete(`/user/${id}`);
  }
};
