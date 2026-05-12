import { useRef } from "react";
import { last } from "lodash-es";
import store, { useAppSelector } from "..";
import { popDialogStack, pushDialogStack, removeDialog } from "../reducer/dialog";

export const useDialogStore = () => {
  const state = useAppSelector((state) => state.dialog);
  const stateRef = useRef(state);
  const apiRef = useRef<ReturnType<typeof buildDialogStoreApi> | null>(null);

  stateRef.current = state;

  if (!apiRef.current) {
    apiRef.current = buildDialogStoreApi(stateRef);
  }

  return apiRef.current!;
};

const buildDialogStoreApi = (stateRef: React.MutableRefObject<ReturnType<typeof store.getState>["dialog"]>) => ({
  get state() {
    return stateRef.current;
  },
  getState: () => {
    return store.getState().dialog;
  },
  pushDialogStack: (dialogName: string) => {
    store.dispatch(pushDialogStack(dialogName));
  },
  popDialogStack: () => {
    store.dispatch(popDialogStack());
  },
  removeDialog: (dialogName: string) => {
    store.dispatch(removeDialog(dialogName));
  },
  topDialogStack: () => {
    return last(store.getState().dialog.dialogStack);
  },
});
