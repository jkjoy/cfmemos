import axios from 'axios';

// API 基础地址
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

// 创建 Axios 实例
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  },
  withCredentials: true  // 支持跨域携带凭证
});

// 请求拦截器 - 添加认证 Token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器 - 统一处理响应和错误
apiClient.interceptors.response.use(
  (response) => {
    // 如果响应中有新的 token，保存它
    const newToken = response.headers['x-token'];
    if (newToken) {
      localStorage.setItem('auth_token', newToken);
    }

    // 返回响应数据
    return response.data;
  },
  (error) => {
    // 处理错误响应
    if (error.response) {
      const { status, data } = error.response;

      // 401 未授权 - 清除 token 并跳转到登录页
      if (status === 401) {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_info');

        // 只有不在登录页时才跳转
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
      }

      // 403 禁止访问
      if (status === 403) {
        console.error('Access denied:', data.error || '没有权限');
      }

      // 返回错误信息
      return Promise.reject(data || { error: 'Request failed' });
    }

    // 网络错误
    if (error.request) {
      return Promise.reject({ error: 'Network error. Please check your connection.' });
    }

    // 其他错误
    return Promise.reject({ error: error.message });
  }
);

export default apiClient;
