import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/**
 * Theme Store - Manages UI theme state
 * Using Zustand with persist middleware
 */
export const useThemeStore = create(
  persist(
    (set, get) => ({
      // Theme state
      theme: 'light', // 'light' or 'dark'
      sidebarCollapsed: false,

      // Actions
      setTheme: (theme) => {
        set({ theme });
        applyTheme(theme);
      },

      toggleTheme: () => {
        const newTheme = get().theme === 'light' ? 'dark' : 'light';
        set({ theme: newTheme });
        applyTheme(newTheme);
      },

      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),

      // Initialize theme on mount
      initialize: () => {
        const theme = get().theme;
        applyTheme(theme);
      }
    }),
    {
      name: 'theme-storage', // localStorage key
    }
  )
);

/**
 * Apply theme to document
 */
function applyTheme(theme) {
  if (theme === 'dark') {
    document.documentElement.classList.add('dark-theme');
  } else {
    document.documentElement.classList.remove('dark-theme');
  }
}
