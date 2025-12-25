import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/**
 * 认证状态管理 Store
 */
export const useAuthStore = create(
  persist(
    (set, get) => ({
      // 状态
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,

      // 设置认证信息
      setAuth: (user, token) => {
        if (token) {
          localStorage.setItem('auth_token', token);
        }
        if (user) {
          localStorage.setItem('user_info', JSON.stringify(user));
        }
        set({
          user,
          token,
          isAuthenticated: true
        });
      },

      // 更新用户信息
      setUser: (user) => {
        if (user) {
          localStorage.setItem('user_info', JSON.stringify(user));
        }
        set({ user });
      },

      // 登出
      logout: () => {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_info');
        set({
          user: null,
          token: null,
          isAuthenticated: false
        });
      },

      // 设置加载状态
      setLoading: (isLoading) => {
        set({ isLoading });
      },

      // 检查是否是管理员
      isAdmin: () => {
        const { user } = get();
        return user?.is_admin === 1 || user?.role === 'ADMIN';
      },

      // 初始化认证状态（从 localStorage 恢复）
      initialize: () => {
        const token = localStorage.getItem('auth_token');
        const userStr = localStorage.getItem('user_info');

        if (token && userStr) {
          try {
            const user = JSON.parse(userStr);
            set({
              user,
              token,
              isAuthenticated: true
            });
          } catch (error) {
            console.error('Failed to parse user info:', error);
            get().logout();
          }
        }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        token: state.token,
        user: state.user,
        isAuthenticated: state.isAuthenticated
      })
    }
  )
);
