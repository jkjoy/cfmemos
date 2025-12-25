import apiClient from './client';

/**
 * 资源 API
 */
export const resourceAPI = {
  /**
   * 获取资源列表
   * @param {Object} params - 查询参数
   */
  list: (params = {}) => {
    return apiClient.get('/resource', { params });
  },

  /**
   * 获取资源元数据
   * @param {string|number} id - 资源 ID
   */
  get: (id) => {
    return apiClient.get(`/resource/${id}`);
  },

  /**
   * 获取资源文件 URL
   * @param {string|number} id - 资源 ID
   */
  getFileUrl: (id) => {
    return `${apiClient.defaults.baseURL}/resource/${id}/file`;
  },

  /**
   * 上传资源
   * @param {File} file - 文件对象
   * @param {Function} onProgress - 上传进度回调
   */
  upload: (file, onProgress) => {
    const formData = new FormData();
    formData.append('file', file);

    return apiClient.post('/resource', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const percentCompleted = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          );
          onProgress(percentCompleted);
        }
      }
    });
  },

  /**
   * 删除资源
   * @param {string|number} id - 资源 ID
   */
  delete: (id) => {
    return apiClient.delete(`/resource/${id}`);
  }
};
