import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Hash } from "lucide-react";
import { memoAPI } from "@/api/memos";
import Memo from "@/components/Memo";
import { Memo as MemoType } from "@/types";
import { useTranslation } from "react-i18next";

/**
 * Explore Page
 * Public memos discovery page
 * Based on Memos 0.18.1 Explore page
 */
export default function Explore() {
  const { t } = useTranslation();

  // Fetch public memos
  const { data: memos = [], isLoading, error } = useQuery({
    queryKey: ["memos", "explore"],
    queryFn: () => memoAPI.list({ limit: 100, visibility: "PUBLIC" }),
  });

  // Sort by created time (newest first)
  const sortedMemos = useMemo(() => {
    return [...memos].sort((a, b) => b.createdTs - a.createdTs);
  }, [memos]);

  return (
    <div className="w-full max-w-4xl mx-auto px-4 py-6">
      {/* Page Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-3 bg-gradient-to-br from-blue-500 to-indigo-600 rounded-lg">
            <Hash className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gray-800 dark:text-gray-100">
              {t("nav.explore")}
            </h1>
            <p className="text-gray-600 dark:text-gray-400 text-sm">
              发现公开的备忘录和想法
            </p>
          </div>
        </div>

        {/* Stats */}
        {!isLoading && (
          <div className="text-sm text-gray-500 dark:text-gray-400">
            共找到 <span className="font-semibold text-gray-700 dark:text-gray-300">{sortedMemos.length}</span> 条公开备忘录
          </div>
        )}
      </div>

      {/* Loading State */}
      {isLoading && (
        <div className="w-full flex justify-center items-center py-12">
          <div className="text-gray-500 dark:text-gray-400">
            加载中...
          </div>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="w-full flex justify-center items-center py-12">
          <div className="text-red-600 dark:text-red-400">
            加载失败: {(error as Error).message}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!isLoading && !error && sortedMemos.length === 0 && (
        <div className="w-full flex flex-col justify-center items-center py-16">
          <div className="p-4 bg-gray-100 dark:bg-zinc-700 rounded-full mb-4">
            <Hash className="w-12 h-12 text-gray-400 dark:text-gray-500" />
          </div>
          <div className="text-gray-500 dark:text-gray-400 text-lg mb-2">
            还没有公开的备忘录
          </div>
          <div className="text-gray-400 dark:text-gray-500 text-sm">
            等待第一条公开备忘录的出现
          </div>
        </div>
      )}

      {/* Memo List */}
      {!isLoading && !error && sortedMemos.length > 0 && (
        <div className="w-full flex flex-col justify-start items-start">
          {sortedMemos.map((memo: MemoType, index) => (
            <Memo
              key={memo.id}
              memo={memo}
              showCreator={true}
              showVisibility={false}
              showPinnedStyle={false}
              lazyRendering={index > 10}
            />
          ))}
        </div>
      )}
    </div>
  );
}
