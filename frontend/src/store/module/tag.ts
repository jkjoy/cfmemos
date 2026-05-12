import { useRef } from "react";
import { tagServiceClient } from "@/grpcweb";
import useCurrentUser from "@/hooks/useCurrentUser";
import store, { useAppSelector } from "..";
import { deleteTag as deleteTagAction, setTags, upsertTag as upsertTagAction } from "../reducer/tag";

export const useTagStore = () => {
  const state = useAppSelector((state) => state.tag);
  const currentUser = useCurrentUser();
  const stateRef = useRef(state);
  const currentUserNameRef = useRef(currentUser.name);
  const apiRef = useRef<ReturnType<typeof buildTagStoreApi> | null>(null);

  stateRef.current = state;
  currentUserNameRef.current = currentUser.name;

  if (!apiRef.current) {
    apiRef.current = buildTagStoreApi(stateRef, currentUserNameRef);
  }

  return apiRef.current!;
};

const buildTagStoreApi = (
  stateRef: React.MutableRefObject<ReturnType<typeof store.getState>["tag"]>,
  currentUserNameRef: React.MutableRefObject<string>
) => ({
  get state() {
    return stateRef.current;
  },
  getState: () => {
    return store.getState().tag;
  },
  fetchTags: async () => {
    const { tags } = await tagServiceClient.listTags({
      user: currentUserNameRef.current,
    });
    store.dispatch(setTags(tags.map((tag) => tag.name)));
  },
  upsertTag: async (tagName: string) => {
    await tagServiceClient.upsertTag({
      name: tagName,
    });
    store.dispatch(upsertTagAction(tagName));
  },
  deleteTag: async (tagName: string) => {
    await tagServiceClient.deleteTag({
      tag: {
        name: tagName,
        creator: currentUserNameRef.current,
      },
    });
    store.dispatch(deleteTagAction(tagName));
  },
});
