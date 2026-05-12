import { useEffect, useState } from "react";
import { toast } from "react-hot-toast";
import { userServiceClient } from "@/grpcweb";
import useCurrentUser from "@/hooks/useCurrentUser";
import { useGlobalStore } from "@/store/module";
import { useTranslate } from "@/utils/i18n";
import { generateDialog } from "./Dialog";
import Icon from "./Icon";

type Props = DialogProps;

const ChangePasswordDialog: React.FC<Props> = ({ destroy }: Props) => {
  const t = useTranslate();
  const currentUser = useCurrentUser();
  const globalStore = useGlobalStore();
  const profile = globalStore.state.systemStatus.profile;
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordAgain, setNewPasswordAgain] = useState("");

  useEffect(() => {
    if (profile.mode === "demo") {
      toast.error("Demo mode does not support this operation.");
      destroy();
    }
  }, [destroy, profile.mode]);

  const handleCloseBtnClick = () => {
    destroy();
  };

  const handleCurrentPasswordChanged = (e: React.ChangeEvent<HTMLInputElement>) => {
    const text = e.target.value as string;
    setCurrentPassword(text);
  };

  const handleNewPasswordChanged = (e: React.ChangeEvent<HTMLInputElement>) => {
    const text = e.target.value as string;
    setNewPassword(text);
  };

  const handleNewPasswordAgainChanged = (e: React.ChangeEvent<HTMLInputElement>) => {
    const text = e.target.value as string;
    setNewPasswordAgain(text);
  };

  const handleSaveBtnClick = async () => {
    if (currentPassword === "" || newPassword === "" || newPasswordAgain === "") {
      toast.error(t("message.fill-all"));
      return;
    }

    if (newPassword !== newPasswordAgain) {
      toast.error(t("message.new-password-not-match"));
      setNewPasswordAgain("");
      return;
    }

    try {
      await userServiceClient.updateUserPassword({
        id: currentUser.id,
        currentPassword,
        newPassword,
      });
      toast.success(t("message.password-changed"));
      handleCloseBtnClick();
    } catch (error: any) {
      console.error(error);
      toast.error(error.message || "Failed to update password");
    }
  };

  return (
    <>
      <div className="dialog-header-container !w-64">
        <p className="title-text">{t("setting.account-section.change-password")}</p>
        <button className="btn close-btn" onClick={handleCloseBtnClick}>
          <Icon.X />
        </button>
      </div>
      <form
        className="dialog-content-container"
        onSubmit={(event) => {
          event.preventDefault();
          handleSaveBtnClick();
        }}
      >
        <p className="text-sm mb-1">{t("common.password")}</p>
        <input
          type="password"
          autoComplete="current-password"
          className="input-text"
          placeholder={t("common.password")}
          value={currentPassword}
          onChange={handleCurrentPasswordChanged}
        />
        <p className="text-sm mb-1 mt-2">{t("auth.new-password")}</p>
        <input
          type="password"
          autoComplete="new-password"
          className="input-text"
          placeholder={t("auth.new-password")}
          value={newPassword}
          onChange={handleNewPasswordChanged}
        />
        <p className="text-sm mb-1 mt-2">{t("auth.repeat-new-password")}</p>
        <input
          type="password"
          autoComplete="new-password"
          className="input-text"
          placeholder={t("auth.repeat-new-password")}
          value={newPasswordAgain}
          onChange={handleNewPasswordAgainChanged}
        />
        <div className="mt-4 w-full flex flex-row justify-end items-center space-x-2">
          <span className="btn-text" onClick={handleCloseBtnClick}>
            {t("common.cancel")}
          </span>
          <button type="submit" className="btn-primary">
            {t("common.save")}
          </button>
        </div>
      </form>
    </>
  );
};

function showChangePasswordDialog() {
  generateDialog(
    {
      className: "change-password-dialog",
      dialogName: "change-password-dialog",
    },
    ChangePasswordDialog
  );
}

export default showChangePasswordDialog;
