import { useRef } from "react";
import { omit } from "lodash-es";
import * as api from "@/helpers/api";
import { DEFAULT_MEMO_LIMIT } from "@/helpers/consts";
import store, { useAppSelector } from "../";
import { updateLoadingStatus, createMemo, deleteMemo, patchMemo, upsertMemos, clearMemos, LoadingStatus } from "../reducer/memo";
import { useMemoCacheStore } from "../v1";

export const convertResponseModelMemo = (memo: Memo): Memo => {
  return {
    ...memo,
    createdTs: memo.createdTs * 1000,
    updatedTs: memo.updatedTs * 1000,
    displayTs: memo.displayTs * 1000,
  };
};

export const useMemoStore = () => {
  const state = useAppSelector((state) => state.memo);
  const setMemoCache = useMemoCacheStore((memoCacheStore) => memoCacheStore.setMemoCache);
  const deleteMemoCache = useMemoCacheStore((memoCacheStore) => memoCacheStore.deleteMemoCache);
  const stateRef = useRef(state);
  const apiRef = useRef<ReturnType<typeof buildMemoStoreApi> | null>(null);

  stateRef.current = state;

  if (!apiRef.current) {
    apiRef.current = buildMemoStoreApi(stateRef, { setMemoCache, deleteMemoCache });
  }

  return apiRef.current!;
};

const buildMemoStoreApi = (
  stateRef: React.MutableRefObject<ReturnType<typeof store.getState>["memo"]>,
  memoCacheStore: {
    setMemoCache: (memo: Memo) => void;
    deleteMemoCache: (memoId: MemoId) => void;
  }
) => {
  const fetchMemoById = async (memoId: MemoId) => {
    const { data } = await api.getMemoById(memoId);
    const memo = convertResponseModelMemo(data);
    store.dispatch(upsertMemos([memo]));
    memoCacheStore.setMemoCache(memo);

    return memo;
  };

  return {
    get state() {
      return stateRef.current;
    },
    getState: () => {
      return store.getState().memo;
    },
    fetchMemos: async (username = "", limit = DEFAULT_MEMO_LIMIT, offset = 0, filter?: { text?: string; tag?: string; dateFrom?: number; dateTo?: number }) => {
      const memoFind: MemoFind = {
        rowStatus: "NORMAL",
        limit,
        offset,
      };
      if (username) {
        memoFind.creatorUsername = username;
      }
      if (filter?.text) {
        memoFind.text = filter.text;
      }
      if (filter?.tag) {
        memoFind.tag = filter.tag;
      }
      if (filter?.dateFrom) {
        memoFind.dateFrom = Math.floor(filter.dateFrom / 1000);
      }
      if (filter?.dateTo) {
        memoFind.dateTo = Math.floor(filter.dateTo / 1000);
      }

      store.dispatch(updateLoadingStatus("fetching"));
      const { data } = await api.getMemoList(memoFind);
      const fetchedMemos = data.map((m) => convertResponseModelMemo(m));
      store.dispatch(upsertMemos(fetchedMemos));
      store.dispatch(updateLoadingStatus(fetchedMemos.length === limit ? "incomplete" : "complete"));

      for (const m of fetchedMemos) {
        memoCacheStore.setMemoCache(m);
      }

      return fetchedMemos;
    },
    fetchAllMemos: async (limit = DEFAULT_MEMO_LIMIT, offset?: number) => {
      const memoFind: MemoFind = {
        rowStatus: "NORMAL",
        limit,
        offset,
      };

      store.dispatch(updateLoadingStatus("fetching"));
      const { data } = await api.getAllMemos(memoFind);
      const fetchedMemos = data.map((m) => convertResponseModelMemo(m));
      store.dispatch(upsertMemos(fetchedMemos));
      store.dispatch(updateLoadingStatus(fetchedMemos.length === limit ? "incomplete" : "complete"));

      for (const m of fetchedMemos) {
        memoCacheStore.setMemoCache(m);
      }

      return fetchedMemos;
    },
    fetchArchivedMemos: async () => {
      const memoFind: MemoFind = {
        rowStatus: "ARCHIVED",
      };
      const { data } = await api.getMemoList(memoFind);
      const archivedMemos = data.map((m) => convertResponseModelMemo(m));
      return archivedMemos;
    },
    setLoadingStatus: (status: LoadingStatus) => {
      store.dispatch(updateLoadingStatus(status));
    },
    fetchMemoById,
    getMemoById: async (memoId: MemoId) => {
      for (const m of stateRef.current.memos) {
        if (m.id === memoId) {
          return m;
        }
      }

      return await fetchMemoById(memoId);
    },
    getLinkedMemos: async (memoId: MemoId): Promise<Memo[]> => {
      const regex = new RegExp(`[@(.+?)](${memoId})`);
      return stateRef.current.memos.filter((m) => m.content.match(regex));
    },
    createMemo: async (memoCreateValue: MemoCreate) => {
      const { data } = await api.createMemo(memoCreateValue);
      const memo = convertResponseModelMemo(data);
      store.dispatch(createMemo(memo));
      memoCacheStore.setMemoCache(memo);
      return memo;
    },
    patchMemo: async (memoPatchValue: MemoPatch): Promise<Memo> => {
      const { data } = await api.patchMemo(memoPatchValue);
      const memo = convertResponseModelMemo(data);
      store.dispatch(patchMemo(omit(memo, "pinned")));
      memoCacheStore.setMemoCache(memo);
      return memo;
    },
    pinMemo: async (memoId: MemoId) => {
      await api.pinMemo(memoId);
      store.dispatch(
        patchMemo({
          id: memoId,
          pinned: true,
        })
      );
    },
    unpinMemo: async (memoId: MemoId) => {
      await api.unpinMemo(memoId);
      store.dispatch(
        patchMemo({
          id: memoId,
          pinned: false,
        })
      );
    },
    deleteMemoById: async (memoId: MemoId) => {
      await api.deleteMemo(memoId);
      store.dispatch(deleteMemo(memoId));
      memoCacheStore.deleteMemoCache(memoId);
    },
    clearMemos: () => {
      store.dispatch(clearMemos());
    },
  };
};
