import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Button, Input, FormControl, FormLabel, Alert, Divider } from "@mui/joy";
import { LogIn } from "lucide-react";
import { useAuthStore } from "@/store/authStore";
import { userAPI } from "@/api/users";
import * as api from "@/helpers/api";
import { absolutifyLink } from "@/helpers/utils";
import { useTranslation } from "react-i18next";

/**
 * Login Page
 * User authentication page with Tailwind + MUI Joy
 * Based on Memos 0.18.1 login design
 */
export default function Login() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const setAuth = useAuthStore((state) => state.setAuth);

  const [formData, setFormData] = useState({
    username: "",
    password: "",
  });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [identityProviders, setIdentityProviders] = useState<IdentityProvider[]>([]);

  useEffect(() => {
    // 加载SSO提供商列表
    api.getIdentityProviderList()
      .then(({ data }) => setIdentityProviders(data))
      .catch((err) => console.error("Failed to load SSO providers:", err));
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
    setError("");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await userAPI.login(formData);

      if (response.token && response.user) {
        setAuth(response.user, response.token);
        navigate("/");
      } else {
        setError("登录响应格式错误");
      }
    } catch (err: any) {
      setError(err.error || err.message || "登录失败，请检查用户名和密码");
    } finally {
      setLoading(false);
    }
  };

  const handleSSOLogin = (provider: IdentityProvider) => {
    // 生成OAuth2授权URL
    const redirectUri = absolutifyLink("/auth/callback");
    const state = `sso-${provider.id}`;

    let authUrl = "";
    const config = provider.config as any;

    switch (provider.type) {
      case "google":
        authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${config.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20profile%20email&state=${state}`;
        break;
      case "github":
        authUrl = `https://github.com/login/oauth/authorize?client_id=${config.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=user:email&state=${state}`;
        break;
      case "gitlab":
        const instanceUrl = config.instanceUrl || "https://gitlab.com";
        authUrl = `${instanceUrl}/oauth/authorize?client_id=${config.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20profile%20email&state=${state}`;
        break;
      case "oidc":
        authUrl = `${config.authUrl}?client_id=${config.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20profile%20email&state=${state}`;
        break;
    }

    if (authUrl) {
      window.location.href = authUrl;
    }
  };

  return (
    <div className="w-full max-w-md mx-auto p-8">
      {/* Logo/Title */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-800 dark:text-gray-100 mb-2">
          Cloudflare Memos
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          {t("auth.login")}
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <Alert color="danger" className="mb-4">
          {error}
        </Alert>
      )}

      {/* Login Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <FormControl>
          <FormLabel>{t("auth.username")}</FormLabel>
          <Input
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            required
            autoFocus
            size="lg"
          />
        </FormControl>

        <FormControl>
          <FormLabel>{t("auth.password")}</FormLabel>
          <Input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            required
            size="lg"
          />
        </FormControl>

        <Button
          type="submit"
          loading={loading}
          fullWidth
          size="lg"
          startDecorator={<LogIn className="w-5 h-5" />}
        >
          {loading ? "登录中..." : t("auth.login")}
        </Button>
      </form>

      {/* SSO Login Options */}
      {identityProviders.length > 0 && (
        <>
          <Divider className="my-6">或使用</Divider>
          <div className="space-y-2">
            {identityProviders.map((provider) => (
              <Button
                key={provider.id}
                variant="outlined"
                color="neutral"
                fullWidth
                size="lg"
                onClick={() => handleSSOLogin(provider)}
              >
                使用 {provider.name} 登录
              </Button>
            ))}
          </div>
        </>
      )}

      {/* Register Link */}
      <div className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
        还没有账号？{" "}
        <Link
          to="/register"
          className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
        >
          立即注册
        </Link>
      </div>
    </div>
  );
}
