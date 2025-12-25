import { useEffect, useRef } from "react";
import { toast } from "react-hot-toast";
import { useParams } from "react-router-dom";
import MemoFilter from "@/components/MemoFilter";
import { DEFAULT_MEMO_LIMIT } from "@/helpers/consts";
import { getTimeStampByDate } from "@/helpers/datetime";
import useCurrentUser from "@/hooks/useCurrentUser";
import { TAG_REG } from "@/labs/marked/parser";
import { useFilterStore, useGlobalStore, useMemoStore } from "@/store/module";
import { extractUsernameFromName } from "@/store/v1";
import { useTranslate } from "@/utils/i18n";
import Empty from "./Empty";
import Memo from "./Memo";

const MemoList: React.FC = () => {
  const t = useTranslate();
  const params = useParams();
  const globalStore = useGlobalStore();
  const memoStore = useMemoStore();
  const filterStore = useFilterStore();
  const filter = filterStore.state;
  const { loadingStatus, memos } = memoStore.state;
  const systemStatus = globalStore.state.systemStatus;
  const user = useCurrentUser();
  const { tag: tagQuery, duration, text: textQuery, visibility } = filter;
  const showMemoFilter = Boolean(tagQuery || (duration && duration.from < duration.to) || textQuery || visibility);
  const username = params.username || extractUsernameFromName(user.name);

  const fetchMoreRef = useRef<HTMLSpanElement>(null);

  const shownMemos = memos.filter((memo) => memo.creatorUsername === username && memo.rowStatus === "NORMAL");

  const pinnedMemos = shownMemos.filter((m) => m.pinned);
  const unpinnedMemos = shownMemos.filter((m) => !m.pinned);
  const memoSort = (mi: Memo, mj: Memo) => {
    // 如果设置了按更新时间排序，使用 updatedTs，否则使用 displayTs
    if (systemStatus.memoDisplayWithUpdatedTs) {
      return mj.updatedTs - mi.updatedTs;
    }
    return mj.displayTs - mi.displayTs;
  };
  pinnedMemos.sort(memoSort);
  unpinnedMemos.sort(memoSort);
  const sortedMemos = pinnedMemos.concat(unpinnedMemos).filter((m) => m.rowStatus === "NORMAL");

  useEffect(() => {
    const root = document.body.querySelector("#root");
    if (root) {
      root.scrollTo(0, 0);
    }

    // 当filter变化时，清除现有memos并重新加载
    memoStore.clearMemos(); // 清除现有 memos
    memoStore.setLoadingStatus("incomplete");

    (async () => {
      try {
        // 准备搜索参数
        const searchFilter: any = {};
        if (textQuery) searchFilter.text = textQuery;
        if (tagQuery) searchFilter.tag = tagQuery;
        if (duration && duration.from < duration.to) {
          searchFilter.dateFrom = duration.from;
          searchFilter.dateTo = duration.to;
        }

        await memoStore.fetchMemos(username, DEFAULT_MEMO_LIMIT, 0, searchFilter);
      } catch (error: any) {
        toast.error(error.response?.data?.message || "Failed to fetch memos");
      }
    })();
  }, [filter]);

  useEffect(() => {
    memoStore.setLoadingStatus("incomplete");
  }, []);

  useEffect(() => {
    if (!fetchMoreRef.current) return;

    const observer = new IntersectionObserver(([entry]) => {
      if (!entry.isIntersecting) return;
      observer.disconnect();
      handleFetchMoreClick();
    });
    observer.observe(fetchMoreRef.current);

    return () => observer.disconnect();
  }, [loadingStatus]);

  const handleFetchMoreClick = async () => {
    try {
      // 准备搜索参数
      const searchFilter: any = {};
      if (textQuery) searchFilter.text = textQuery;
      if (tagQuery) searchFilter.tag = tagQuery;
      if (duration && duration.from < duration.to) {
        searchFilter.dateFrom = duration.from;
        searchFilter.dateTo = duration.to;
      }

      await memoStore.fetchMemos(username, DEFAULT_MEMO_LIMIT, memos.length, searchFilter);
    } catch (error: any) {
      toast.error(error.response?.data?.message || "Failed to fetch more memos");
    }
  };

  return (
    <div className="flex flex-col justify-start items-start w-full max-w-full overflow-y-scroll pb-28 hide-scrollbar">
      <MemoFilter />
      {sortedMemos.map((memo) => (
        <Memo key={memo.id} memo={memo} lazyRendering showVisibility showPinnedStyle showParent />
      ))}

      {loadingStatus === "fetching" ? (
        <div className="flex flex-col justify-start items-center w-full mt-2 mb-1">
          <p className="text-sm text-gray-400 italic">{t("memo.fetching-data")}</p>
        </div>
      ) : (
        <div className="flex flex-col justify-start items-center w-full my-6">
          <div className="text-gray-400 italic">
            {loadingStatus === "complete" ? (
              sortedMemos.length === 0 && (
                <div className="w-full mt-12 mb-8 flex flex-col justify-center items-center italic">
                  <Empty />
                  <p className="mt-2 text-gray-600 dark:text-gray-400">{t("message.no-data")}</p>
                </div>
              )
            ) : (
              <span ref={fetchMoreRef} className="cursor-pointer hover:text-green-600" onClick={handleFetchMoreClick}>
                {t("memo.fetch-more")}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default MemoList;
