import { useEffect } from "react";
import useCurrentUser from "@/hooks/useCurrentUser";
import useNavigateTo from "@/hooks/useNavigateTo";

interface Props {
  children: React.ReactNode;
}

const AuthStatusProvider = (props: Props) => {
  const navigateTo = useNavigateTo();
  const currentUser = useCurrentUser();

  useEffect(() => {
    // 如果没有当前用户，检查是否应该重定向
    if (!currentUser) {
      const hasToken = Boolean(localStorage.getItem('auth-token'));

      // 如果有token但没有user，说明session已失效，清除token并重定向
      if (hasToken) {
        console.log('Session expired or invalid, clearing token');
        localStorage.removeItem('auth-token');
      }

      // 重定向到explore页面
      navigateTo("/explore");
    }
  }, [currentUser, navigateTo]);

  // 如果没有currentUser，不渲染children
  if (!currentUser) {
    return null;
  }

  return <>{props.children}</>;
};

export default AuthStatusProvider;
