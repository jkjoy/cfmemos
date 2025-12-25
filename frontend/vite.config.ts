import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },

  optimizeDeps: {
    exclude: ['@/types/proto'],
    esbuildOptions: {
      // 忽略依赖扫描错误
      logLevel: 'silent',
    },
  },

  server: {
    port: 5173,
    proxy: {
      // 代理 API 请求到后端开发服务器
      '/api': {
        target: 'http://127.0.0.1:8787',
        changeOrigin: true,
        secure: false,
      },
      // 代理资源文件请求到后端
      '/o': {
        target: 'http://127.0.0.1:8787',
        changeOrigin: true,
        secure: false,
      }
    }
  },

  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // 代码分割优化
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'router': ['react-router-dom'],
          'query': ['@tanstack/react-query'],
          'markdown': ['react-markdown', 'remark-gfm', 'rehype-sanitize']
        }
      }
    }
  }
})
