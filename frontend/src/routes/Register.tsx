import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Button, Input, FormControl, FormLabel, Alert } from "@mui/joy";
import { UserPlus } from "lucide-react";
import { useAuthStore } from "@/store/authStore";
import { userAPI } from "@/api/users";
import { useTranslation } from "react-i18next";

/**
 * Register Page
 * User registration page with Tailwind + MUI Joy
 * Based on Memos 0.18.1 register design
 */
export default function Register() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const setAuth = useAuthStore((state) => state.setAuth);

  const [formData, setFormData] = useState({
    username: "",
    password: "",
    nickname: "",
  });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

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

    // Validation
    if (formData.password.length < 6) {
      setError("密码至少需要 6 个字符");
      return;
    }

    setLoading(true);

    try {
      const response = await userAPI.register(formData);

      if (response.token && response.user) {
        setAuth(response.user, response.token);
        navigate("/");
      } else {
        setError("注册响应格式错误");
      }
    } catch (err: any) {
      setError(err.error || err.message || "注册失败");
    } finally {
      setLoading(false);
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
          {t("auth.register")}
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <Alert color="danger" className="mb-4">
          {error}
        </Alert>
      )}

      {/* Register Form */}
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
            placeholder="字母、数字、下划线"
          />
        </FormControl>

        <FormControl>
          <FormLabel>昵称</FormLabel>
          <Input
            type="text"
            name="nickname"
            value={formData.nickname}
            onChange={handleChange}
            size="lg"
            placeholder="显示名称 (可选)"
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
            placeholder="至少 6 个字符"
          />
        </FormControl>

        <Button
          type="submit"
          loading={loading}
          fullWidth
          size="lg"
          startDecorator={<UserPlus className="w-5 h-5" />}
        >
          {loading ? "注册中..." : t("auth.register")}
        </Button>
      </form>

      {/* Login Link */}
      <div className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
        已有账号？{" "}
        <Link
          to="/login"
          className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
        >
          立即登录
        </Link>
      </div>
    </div>
  );
}
