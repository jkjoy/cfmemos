import { IconButton, Option, Select, Tooltip } from "@mui/joy";
import copy from "copy-to-clipboard";
import { useCallback, useEffect, useState } from "react";
import { toast } from "react-hot-toast";
import { Link } from "react-router-dom";
import FloatingNavButton from "@/components/FloatingNavButton";
import Icon from "@/components/Icon";
import MemoContent from "@/components/MemoContent";
import showMemoEditorDialog from "@/components/MemoEditor/MemoEditorDialog";
import MemoRelationListView from "@/components/MemoRelationListView";
import MemoResourceListView from "@/components/MemoResourceListView";
import showShareMemoDialog from "@/components/ShareMemoDialog";
import UserAvatar from "@/components/UserAvatar";
import VisibilityIcon from "@/components/VisibilityIcon";
import { VISIBILITY_SELECTOR_ITEMS } from "@/helpers/consts";
import { getDateTimeString } from "@/helpers/datetime";
import useCurrentUser from "@/hooks/useCurrentUser";
import useNavigateTo from "@/hooks/useNavigateTo";
import { useGlobalStore, useMemoStore } from "@/store/module";
import { useUserV1Store, extractUsernameFromName } from "@/store/v1";
import { User, User_Role } from "@/types/proto/api/v2/user_service";
import { useTranslate } from "@/utils/i18n";

interface Props {
  memoId: MemoId;
  mode?: "page" | "modal";
  onClose?: () => void;
}

const MemoDetailContent: React.FC<Props> = ({ memoId, mode = "page", onClose }) => {
  const t = useTranslate();
  const navigateTo = useNavigateTo();
  const currentUser = useCurrentUser();
  const globalStore = useGlobalStore();
  const memoStore = useMemoStore();
  const getOrFetchUserByUsername = useUserV1Store((state) => state.getOrFetchUserByUsername);
  const [creator, setCreator] = useState<User>();
  const [isPreparing, setIsPreparing] = useState<boolean>(true);
  const { systemStatus } = globalStore.state;
  const memo = memoStore.state.memos.find((memo) => memo.id === memoId);
  const allowEdit = memo?.creatorUsername === extractUsernameFromName(currentUser?.name);
  const referenceRelations = memo?.relationList.filter((relation) => relation.type === "REFERENCE") || [];

  const handleMissingMemo = useCallback((error?: any) => {
    if (error) {
      console.error(error);
    }

    if (mode === "page") {
      navigateTo("/404");
      return;
    }

    toast.error(error?.response?.data?.message || error?.response?.data?.error || t("message.memo-not-found"));
    onClose?.();
  }, [mode, navigateTo, onClose, t]);

  useEffect(() => {
    let cancelled = false;

    if (!memoId || isNaN(memoId)) {
      handleMissingMemo();
      return;
    }

    setIsPreparing(true);
    memoStore
      .fetchMemoById(memoId)
      .catch((error) => {
        if (!cancelled) {
          handleMissingMemo(error);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsPreparing(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [handleMissingMemo, memoId, memoStore]);

  useEffect(() => {
    if (!memo) {
      return;
    }

    let cancelled = false;
    const prepareCreator = async () => {
      const user = await getOrFetchUserByUsername(memo.creatorUsername);
      if (!cancelled) {
        setCreator(user);
      }
    };

    prepareCreator();

    return () => {
      cancelled = true;
    };
  }, [getOrFetchUserByUsername, memo]);

  const handleMemoVisibilityOptionChanged = async (value: string) => {
    if (!memo) {
      return;
    }

    const visibilityValue = value as Visibility;
    await memoStore.patchMemo({
      id: memo.id,
      visibility: visibilityValue,
    });
  };

  const handleEditMemoClick = () => {
    if (!memo) {
      return;
    }

    showMemoEditorDialog({
      memoId: memo.id,
    });
  };

  const handleCopyLinkBtnClick = () => {
    if (!memo) {
      return;
    }

    copy(`${window.location.origin}/m/${memo.id}`);
    toast.success(t("message.succeed-copy-link"));
  };

  const handleOpenPageClick = () => {
    if (!memo) {
      return;
    }

    onClose?.();
    navigateTo(`/m/${memo.id}`);
  };

  const disableOption = (value: string) => {
    const isAdminOrHost = currentUser?.role === User_Role.ADMIN || currentUser?.role === User_Role.HOST;

    if (value === "PUBLIC" && !isAdminOrHost) {
      return systemStatus.disablePublicMemos;
    }
    return false;
  };

  const memoMeta = memo && (
    <div className="w-full mt-4 flex flex-col gap-2 sm:flex-row sm:justify-between sm:items-center">
      <div className="flex flex-row flex-wrap justify-start items-center">
        <Tooltip title={"Identifier"} placement="top">
          <span className="text-sm text-gray-500 dark:text-gray-400">#{memo.id}</span>
        </Tooltip>
        <Icon.Dot className="w-4 h-auto text-gray-400 dark:text-zinc-400" />
        <Link to={`/u/${encodeURIComponent(memo.creatorUsername)}`}>
          <Tooltip title={"Creator"} placement="top">
            <span className="flex flex-row justify-start items-center">
              <UserAvatar className="!w-5 !h-5 mr-1" avatarUrl={creator?.avatarUrl} />
              <span className="text-sm text-gray-600 max-w-[12em] truncate dark:text-gray-400">
                {creator?.nickname || memo.creatorUsername}
              </span>
            </span>
          </Tooltip>
        </Link>
        {allowEdit ? (
          <>
            <Icon.Dot className="w-4 h-auto text-gray-400 dark:text-zinc-400" />
            <Select
              className="w-auto text-sm"
              variant="plain"
              value={memo.visibility}
              startDecorator={<VisibilityIcon visibility={memo.visibility} />}
              onChange={(_, visibility) => {
                if (visibility) {
                  handleMemoVisibilityOptionChanged(visibility);
                }
              }}
            >
              {VISIBILITY_SELECTOR_ITEMS.map((item) => (
                <Option key={item} value={item} className="whitespace-nowrap" disabled={disableOption(item)}>
                  {t(`memo.visibility.${item.toLowerCase() as Lowercase<typeof item>}`)}
                </Option>
              ))}
            </Select>
          </>
        ) : (
          <>
            <Icon.Dot className="w-4 h-auto text-gray-400 dark:text-zinc-400" />
            <Tooltip title={t(`memo.visibility.${memo.visibility.toLowerCase()}` as any)} placement="top">
              <span>
                <VisibilityIcon visibility={memo.visibility} />
              </span>
            </Tooltip>
          </>
        )}
      </div>
      <div className="flex flex-row sm:justify-end items-center">
        {allowEdit && (
          <Tooltip title={"Edit"} placement="top">
            <IconButton size="sm" onClick={handleEditMemoClick}>
              <Icon.Edit3 className="w-4 h-auto text-gray-600 dark:text-gray-400" />
            </IconButton>
          </Tooltip>
        )}
        <Tooltip title={"Copy link"} placement="top">
          <IconButton size="sm" onClick={handleCopyLinkBtnClick}>
            <Icon.Link className="w-4 h-auto text-gray-600 dark:text-gray-400" />
          </IconButton>
        </Tooltip>
        <Tooltip title={"Share"} placement="top">
          <IconButton size="sm" onClick={() => showShareMemoDialog(memo)}>
            <Icon.Share className="w-4 h-auto text-gray-600 dark:text-gray-400" />
          </IconButton>
        </Tooltip>
        {mode === "modal" && (
          <Tooltip title={t("memo.view-detail")} placement="top">
            <IconButton size="sm" onClick={handleOpenPageClick}>
              <Icon.ArrowUpRightFromCircle className="w-4 h-auto text-gray-600 dark:text-gray-400" />
            </IconButton>
          </Tooltip>
        )}
      </div>
    </div>
  );

  const memoBody = memo && (
    <>
      {memo.parent && (
        <div className="w-auto mb-4">
          <Link
            className="px-3 py-1 border rounded-full max-w-xs w-auto text-sm flex flex-row justify-start items-center flex-nowrap text-gray-600 dark:text-gray-400 dark:border-gray-500 hover:shadow hover:opacity-80"
            to={`/m/${memo.parent.id}`}
          >
            <Icon.ArrowUpLeftFromCircle className="w-4 h-auto shrink-0 opacity-60" />
            <span className="mx-1 opacity-60">#{memo.parent.id}</span>
            <span className="truncate">{memo.parent.content}</span>
          </Link>
        </div>
      )}
      <div className="w-full mb-4 flex flex-row justify-start items-center mr-1">
        <span className="text-gray-400 select-none">{getDateTimeString(memo.displayTs)}</span>
      </div>
      <MemoContent content={memo.content} />
      <MemoResourceListView resourceList={memo.resourceList} />
      <MemoRelationListView memo={memo} relationList={referenceRelations} />
      {memoMeta}
    </>
  );

  if (isPreparing && !memo) {
    return (
      <div className={`w-full ${mode === "page" ? "min-h-screen" : "min-h-[40vh]"} flex flex-col justify-center items-center`}>
        <Icon.Loader className="w-5 h-auto animate-spin text-gray-400" />
      </div>
    );
  }

  if (!memo) {
    return null;
  }

  if (mode === "modal") {
    return (
      <section className="relative w-full">
        <div className="absolute right-4 top-4 z-10 sm:right-6 sm:top-5">
          <div className="flex items-center gap-1 rounded-full border border-zinc-200 bg-white/90 p-1 shadow-sm backdrop-blur dark:border-zinc-700 dark:bg-zinc-800/90">
            <Tooltip title={t("common.close")} placement="top">
              <IconButton size="sm" variant="plain" onClick={onClose}>
                <Icon.X className="w-4 h-auto text-gray-600 dark:text-gray-300" />
              </IconButton>
            </Tooltip>
          </div>
        </div>
        <div className="w-full bg-white dark:bg-zinc-800">
          <div className="mx-auto flex w-full max-w-3xl flex-col items-start px-4 py-5 pr-16 sm:px-6 sm:py-6 sm:pr-20">{memoBody}</div>
        </div>
      </section>
    );
  }

  return (
    <>
      <section className="relative top-0 w-full min-h-full overflow-x-hidden bg-zinc-100 dark:bg-zinc-900">
        <div className="relative w-full h-auto mx-auto flex flex-col justify-start items-center bg-white dark:bg-zinc-700">
          <div className="w-full flex flex-col justify-start items-center pt-16 pb-8">
            <UserAvatar className="!w-20 !h-20 mb-2 drop-shadow" avatarUrl={systemStatus.customizedProfile.logoUrl} />
            <p className="text-3xl text-black opacity-80 dark:text-gray-200">{systemStatus.customizedProfile.name}</p>
          </div>
          <div className="relative flex-grow max-w-2xl w-full min-h-full flex flex-col justify-start items-start px-4 pb-6">{memoBody}</div>
        </div>
      </section>

      <FloatingNavButton />
    </>
  );
};

export default MemoDetailContent;
