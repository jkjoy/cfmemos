import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuthStore } from "@/store/authStore";
import MemoList from "@/components/MemoList";
import MemoEditor from "@/components/MemoEditor";
import { Plus, LogIn, UserPlus } from "lucide-react";

/**
 * Home Page
 * Main page showing memo list and editor
 * Based on Memos 0.18.1 Home page
 *
 * Behavior:
 * - Logged in: Show user's memos + editor
 * - Not logged in: Show public memos + welcome banner
 */
export default function Home() {
  const user = useAuthStore((state) => state.user);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const [showEditor, setShowEditor] = useState(false);

  const handleCreateMemo = () => {
    setShowEditor(true);
  };

  const handleEditorConfirm = () => {
    setShowEditor(false);
  };

  const handleEditorCancel = () => {
    setShowEditor(false);
  };

  return (
    <div className="w-full max-w-4xl mx-auto px-4 py-6">
      {/* Logged In - Welcome Banner with Create Button */}
      {isAuthenticated && user && !showEditor && (
        <div className="w-full mb-6 p-6 bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-zinc-800 dark:to-zinc-700 rounded-lg border border-blue-100 dark:border-zinc-600">
          <h2 className="text-2xl font-semibold text-gray-800 dark:text-gray-100 mb-2">
            欢迎回来，{user.nickname || user.username}！
          </h2>
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            开始记录你的想法和生活点滴 ✨
          </p>
          <button
            onClick={handleCreateMemo}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            <Plus className="w-5 h-5" />
            创建新备忘录
          </button>
        </div>
      )}

      {/* Not Logged In - Welcome Banner with Sign Up/Sign In Links */}
      {!isAuthenticated && (
        <div className="w-full mb-6 p-6 bg-gradient-to-r from-orange-50 to-red-50 dark:from-zinc-800 dark:to-zinc-700 rounded-lg border border-orange-100 dark:border-zinc-600">
          <h2 className="text-2xl font-semibold text-gray-800 dark:text-gray-100 mb-2">
            欢迎来到 Cloudflare Memos！
          </h2>
          <p className="text-gray-600 dark:text-gray-300 mb-4">
            一个轻量级的自托管备忘录服务。登录后即可创建和管理您的备忘录 📝
          </p>
          <div className="flex gap-3">
            <Link
              to="/register"
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors"
            >
              <UserPlus className="w-5 h-5" />
              注册账号
            </Link>
            <Link
              to="/login"
              className="flex items-center gap-2 px-4 py-2 bg-white dark:bg-zinc-700 hover:bg-gray-50 dark:hover:bg-zinc-600 text-gray-700 dark:text-gray-200 border border-gray-300 dark:border-zinc-600 rounded-lg transition-colors"
            >
              <LogIn className="w-5 h-5" />
              登录
            </Link>
          </div>
        </div>
      )}

      {/* Memo Editor - Only for logged in users */}
      {showEditor && (
        <div className="mb-6">
          <MemoEditor onConfirm={handleEditorConfirm} onCancel={handleEditorCancel} />
        </div>
      )}

      {/* Memo List */}
      <MemoList />
    </div>
  );
}
