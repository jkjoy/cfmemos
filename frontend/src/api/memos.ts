import apiClient from './client';

type MemoApiParams = Record<string, string | number | boolean | undefined>;
type MemoApiPayload = Record<string, unknown>;

/**
 * 备忘录 API
 */
export const memoAPI = {
  /**
   * 获取备忘录列表
   * @param {Object} params - 查询参数
   * @param {number} params.limit - 每页数量
   * @param {number} params.offset - 偏移量
   * @param {string} params.creatorId - 创建者 ID
   * @param {string} params.tag - 标签过滤
   * @param {string} params.visibility - 可见性过滤
   */
  list: (params: MemoApiParams = {}) => {
    return apiClient.get('/memo', { params });
  },

  /**
   * 获取备忘录详情
   * @param {string|number} id - 备忘录 ID
   */
  get: (id: string | number) => {
    return apiClient.get(`/memo/${id}`);
  },

  /**
   * 获取备忘录详情 (别名)
   * @param {string|number} id - 备忘录 ID
   */
  getById: (id: string | number) => {
    return apiClient.get(`/memo/${id}`);
  },

  /**
   * 创建备忘录
   * @param {Object} data - 备忘录数据
   * @param {string} data.content - 内容
   * @param {string} data.visibility - 可见性 (PUBLIC/PRIVATE/PROTECTED)
   */
  create: (data: MemoApiPayload) => {
    return apiClient.post('/memo', data);
  },

  /**
   * 更新备忘录
   * @param {string|number} id - 备忘录 ID
   * @param {Object} data - 更新数据
   */
  update: (id: string | number, data: MemoApiPayload) => {
    return apiClient.put(`/memo/${id}`, data);
  },

  /**
   * 部分更新备忘录
   * @param {string|number} id - 备忘录 ID
   * @param {Object} data - 更新数据
   */
  patch: (id: string | number, data: MemoApiPayload) => {
    return apiClient.patch(`/memo/${id}`, data);
  },

  /**
   * 删除备忘录
   * @param {string|number} id - 备忘录 ID
   */
  delete: (id: string | number) => {
    return apiClient.delete(`/memo/${id}`);
  },

  /**
   * 搜索备忘录
   * @param {string} query - 搜索关键词
   */
  search: (query: string) => {
    return apiClient.get('/memo/search', { params: { query } });
  },

  /**
   * 获取统计数据
   */
  stats: () => {
    return apiClient.get('/memo/stats');
  },

  /**
   * 获取热力图数据
   */
  heatmap: () => {
    return apiClient.get('/memo/stats/heatmap');
  },

  /**
   * 切换备忘录置顶状态
   * @param {string|number} id - 备忘录 ID
   * @param {boolean} pinned - 是否置顶
   * @returns {Promise<Object>} 更新结果
   */
  togglePin: (id: string | number, pinned: boolean) => {
    return apiClient.post(`/memo/${id}/organizer`, { pinned });
  }
};
