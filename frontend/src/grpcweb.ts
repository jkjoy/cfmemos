/**
 * REST API 适配器 - 模拟 gRPC-Web 客户端
 * 将前端的 gRPC-Web 调用转换为 REST API 调用
 */

import { User } from "@/types/proto/api/v2/user_service";

// API 基础 URL - 在开发环境中代理到后端
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

// 通用请求函数
async function request<T>(
  method: string,
  path: string,
  data?: any,
  options?: RequestInit
): Promise<T> {
  const url = `${API_BASE_URL}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options?.headers as Record<string, string>) || {}),
  };

  // 从 localStorage 获取 token
  const token = localStorage.getItem('auth-token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config: RequestInit = {
    method,
    headers,
    credentials: 'include',
    ...options,
  };

  if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    if (data instanceof FormData) {
      delete headers['Content-Type']; // 让浏览器自动设置
      config.body = data;
    } else {
      config.body = JSON.stringify(data);
    }
  }

  try {
    const response = await fetch(url, config);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: response.statusText }));
      const errorMessage = errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`;
      console.error('API Error Response:', errorData);
      throw new Error(errorMessage);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }

    return {} as T;
  } catch (error) {
    console.error(`API request failed: ${method} ${path}`, error);
    throw error;
  }
}

// ============ 认证服务 (AuthService) ============

export const authServiceClient = {
  async getAuthStatus(_request: any = {}) {
    try {
      const data = await request<any>('GET', '/api/v1/auth/status');
      if (!data.user) {
        return { user: null };
      }
      // 使用 User.fromPartial 确保对象格式正确
      const user = User.fromPartial(data.user);
      return { user };
    } catch (error) {
      console.error('getAuthStatus error:', error);
      return { user: null };
    }
  },

  async signIn(req: { username: string; password: string; remember?: boolean }) {
    const data = await request<any>('POST', '/api/v1/auth/signin', {
      username: req.username,
      password: req.password,
      remember: req.remember || false,
    });

    if (data.token) {
      localStorage.setItem('auth-token', data.token);
    }

    // 使用 User.fromPartial 确保对象格式正确
    const user = data.user ? User.fromPartial(data.user) : null;
    return { user };
  },

  async signOut(_request: any = {}) {
    await request('POST', '/api/v1/auth/signout');
    localStorage.removeItem('auth-token');
    return {};
  },

  async signUp(req: { username: string; password: string }) {
    const data = await request<any>('POST', '/api/v1/user', {
      username: req.username,
      password: req.password,
      nickname: req.username,
    });

    return { user: data };
  },
};

// ============ 用户服务 (UserService) ============

export const userServiceClient = {
  async getUser(req: { name: string }) {
    // name 格式: "users/{username}"
    const parts = req.name.split('/');
    const username = parts[parts.length - 1];

    // 先尝试通过 username 获取用户
    const users = await request<any[]>('GET', '/api/v1/user');
    const rawUser = users.find(u => u.username === username);

    if (!rawUser) {
      throw new Error('User not found');
    }

    // 转换字段名和时间格式
    const user = {
      ...rawUser,
      createTime: rawUser.created_ts ? new Date(rawUser.created_ts * 1000).toISOString() : new Date().toISOString(),
      updateTime: rawUser.created_ts ? new Date(rawUser.created_ts * 1000).toISOString() : new Date().toISOString(),
    };

    return { user };
  },

  async listUsers(_request: any = {}) {
    const users = await request<any[]>('GET', '/api/v1/user');
    return { users };
  },

  async updateUser(req: { user: any; updateMask?: string[] }) {
    const user = req.user;
    const parts = user.name?.split('/') || [];
    const username = parts[parts.length - 1];

    // 先获取用户 ID
    const users = await request<any[]>('GET', '/api/v1/user');
    const existingUser = users.find(u => u.username === username);

    if (!existingUser) {
      throw new Error('User not found');
    }

    // Only send fields that are defined and have valid values
    const updateData: any = {};
    if (user.nickname !== undefined && user.nickname !== null) {
      updateData.nickname = user.nickname;
    }
    if (user.email !== undefined && user.email !== null) {
      updateData.email = user.email;
    }
    if (user.avatarUrl !== undefined && user.avatarUrl !== null) {
      updateData.avatarUrl = user.avatarUrl;
    }
    // Only send role if it's a valid role value
    if (user.role && ['host', 'admin', 'user', 'HOST', 'ADMIN', 'USER'].includes(user.role.toLowerCase())) {
      updateData.role = user.role.toLowerCase();
    }
    // Handle rowStatus - convert enum values to strings
    if (user.rowStatus !== undefined && user.rowStatus !== null) {
      // Convert RowStatus enum (1=ACTIVE, 2=ARCHIVED) to strings ('NORMAL', 'ARCHIVED')
      // Note: The frontend component uses enum values like RowStatus.ACTIVE (1) or RowStatus.ARCHIVED (2)
      if (typeof user.rowStatus === 'number') {
        updateData.rowStatus = user.rowStatus === 1 ? 'NORMAL' : 'ARCHIVED';
      } else {
        // If it's already a string, use it directly
        updateData.rowStatus = user.rowStatus;
      }
    }

    const updatedUser = await request('PATCH', `/api/v1/user/${existingUser.id}`, updateData);

    return { user: updatedUser };
  },

  async createUser(req: { user: any }) {
    // 从 name 格式 "users/username" 中提取 username
    const username = req.user.name ? req.user.name.replace(/^users\//, '') : req.user.username;

    // 转换 User_Role 枚举为小写字符串
    // User_Role 枚举: ROLE_UNSPECIFIED=0, HOST=1, ADMIN=2, USER=3
    let roleString = 'user'; // 默认值
    if (req.user.role !== undefined) {
      const roleMap: { [key: number]: string } = {
        1: 'host',    // HOST
        2: 'admin',   // ADMIN
        3: 'user'     // USER
      };
      roleString = roleMap[req.user.role] || 'user';
    }

    const user = await request('POST', '/api/v1/user', {
      username: username,
      password: req.user.password,
      nickname: req.user.nickname || username, // 如果没有 nickname，使用 username 作为默认值
      email: req.user.email || '',
      role: roleString,
    });

    return { user };
  },

  async deleteUser(req: { name: string }) {
    const parts = req.name.split('/');
    const username = parts[parts.length - 1];

    // 先获取用户 ID
    const users = await request<any[]>('GET', '/api/v1/user');
    const user = users.find(u => u.username === username);

    if (!user) {
      throw new Error('User not found');
    }

    await request('DELETE', `/api/v1/user/${user.id}`);
    return {};
  },

  async getUserSetting(_request: any = {}) {
    try {
      const data = await request<any>('GET', '/api/v1/user/setting');
      return { setting: data };
    } catch (error) {
      // 如果获取失败,返回默认设置
      return {
        setting: {
          locale: 'en',
          appearance: 'auto',
          memoVisibility: 'PRIVATE',
        }
      };
    }
  },

  async updateUserSetting(req: { setting: any; updateMask?: string[] }) {
    const setting = await request<any>('POST', '/api/v1/user/setting', {
      locale: req.setting.locale,
      appearance: req.setting.appearance,
      memoVisibility: req.setting.memoVisibility,
      telegramUserId: req.setting.telegramUserId,
    });

    return { setting };
  },

  async listUserAccessTokens(req: { name: string }) {
    try {
      const username = req.name.replace('users/', '');
      const response = await request<any[]>('GET', `/api/v1/user/${username}/access-tokens`);
      return { accessTokens: response || [] };
    } catch (error) {
      console.error('listUserAccessTokens error:', error);
      return { accessTokens: [] };
    }
  },

  async createUserAccessToken(req: { name: string; description: string; expiresAt?: string }) {
    try {
      const username = req.name.replace('users/', '');
      const response = await request<any>('POST', `/api/v1/user/${username}/access-tokens`, {
        description: req.description,
        expiresAt: req.expiresAt,
      });
      return { accessToken: response };
    } catch (error) {
      console.error('createUserAccessToken error:', error);
      throw error;
    }
  },

  async deleteUserAccessToken(req: { name: string; accessToken: string }) {
    try {
      const username = req.name.replace('users/', '');
      await request('DELETE', `/api/v1/user/${username}/access-tokens/${req.accessToken}`);
      return {};
    } catch (error) {
      console.error('deleteUserAccessToken error:', error);
      throw error;
    }
  },
};

// ============ 备忘录服务 (MemoService) ============

export const memoServiceClient = {
  async createMemo(req: { content: string; visibility?: string; resourceIdList?: number[]; relationList?: any[] }) {
    const memo = await request('POST', '/api/v1/memo', {
      content: req.content,
      visibility: req.visibility || 'PRIVATE',
      resourceIdList: req.resourceIdList || [],
      relationList: req.relationList || [],
    });

    return { memo };
  },

  async listMemos(req: any = {}) {
    const params = new URLSearchParams();

    if (req.creatorId) params.append('creatorId', req.creatorId);
    if (req.filter) params.append('filter', req.filter);
    if (req.pageSize) params.append('pageSize', req.pageSize.toString());
    if (req.pageToken) params.append('pageToken', req.pageToken);

    const queryString = params.toString();
    const path = `/api/v1/memo${queryString ? `?${queryString}` : ''}`;
    const memos = await request<any[]>('GET', path);

    return { memos };
  },

  async getMemo(req: { name: string }) {
    const parts = req.name.split('/');
    const memoId = parts[parts.length - 1];
    const memo = await request('GET', `/api/v1/memo/${memoId}`);
    return { memo };
  },

  async updateMemo(req: { memo: any; updateMask?: string[] }) {
    const memo = req.memo;
    const parts = memo.name?.split('/') || [];
    const memoId = parts[parts.length - 1] || memo.id;

    const updatedMemo = await request('PATCH', `/api/v1/memo/${memoId}`, {
      content: memo.content,
      visibility: memo.visibility,
      rowStatus: memo.rowStatus,
      pinned: memo.pinned,
      resourceIdList: memo.resourceIdList,
      relationList: memo.relationList,
    });

    return { memo: updatedMemo };
  },

  async deleteMemo(req: { name: string }) {
    const parts = req.name.split('/');
    const memoId = parts[parts.length - 1];
    await request('DELETE', `/api/v1/memo/${memoId}`);
    return {};
  },
};

// ============ 资源服务 (ResourceService) ============

export const resourceServiceClient = {
  async createResource(req: { filename: string; type?: string; externalLink?: string; content?: Uint8Array }) {
    const formData = new FormData();

    if (req.content) {
      const blob = new Blob([req.content], { type: req.type || 'application/octet-stream' });
      formData.append('file', blob, req.filename);
    } else if (req.externalLink) {
      formData.append('externalLink', req.externalLink);
    }

    const resource = await request('POST', '/api/v1/resource', formData);
    return { resource };
  },

  async listResources(_request: any = {}) {
    const resources = await request<any[]>('GET', '/api/v1/resource');
    return { resources };
  },

  async updateResource(req: { resource: any; updateMask: string[] }) {
    const resource = req.resource;
    const resourceId = resource.id;

    const updatedResource = await request('PATCH', `/api/v1/resource/${resourceId}`, {
      filename: resource.filename,
      memoId: resource.memoId,
    });

    return { resource: updatedResource };
  },

  async deleteResource(req: { name: string }) {
    const parts = req.name.split('/');
    const resourceId = parts[parts.length - 1];
    await request('DELETE', `/api/v1/resource/${resourceId}`);
    return {};
  },
};

// ============ 系统服务 (SystemService) ============

export const systemServiceClient = {
  async getSystemInfo(_request: any = {}) {
    const data = await request('GET', '/api/v1/status');
    return { systemInfo: data };
  },

  async updateSystemInfo(req: { systemInfo: any }) {
    const data = await request('PATCH', '/api/v1/settings/system', req.systemInfo);
    return { systemInfo: data };
  },
};

// ============ 标签服务 (TagService) ============

export const tagServiceClient = {
  async listTags(req: { user?: string } = {}) {
    const userId = req.user?.split('/')[1];
    const path = userId ? `/api/v1/tag?userId=${userId}` : '/api/v1/tag';
    const tags = await request<any[]>('GET', path);
    return { tags };
  },

  async upsertTag(req: { name: string }) {
    const data = await request<any>('POST', '/api/v1/tag', req);
    return { data };
  },

  async deleteTag(req: { tag: any }) {
    await request('POST', '/api/v1/tag/delete', { name: req.tag.name });
    return {};
  },

  async getTagSuggestions(req: { user?: string } = {}) {
    try {
      // 暂时返回空数组，后续实现后端 API
      return { tags: [] };
    } catch (error) {
      console.error('getTagSuggestions error:', error);
      return { tags: [] };
    }
  },
};

// ============ Inbox 服务 (InboxService) ============

export const inboxServiceClient = {
  async listInboxes(_request: any = {}) {
    // 暂时返回空列表
    return { inboxes: [] };
  },

  async updateInbox(req: { inbox: any; updateMask?: string[] }) {
    return { inbox: req.inbox };
  },

  async deleteInbox(_request: { name: string }) {
    return {};
  },
};

// ============ Activity 服务 (ActivityService) ============

export const activityServiceClient = {
  async getActivity(_request: { name: string }) {
    return { activity: {} };
  },
};

// ============ Webhook 服务 (WebhookService) ============

export const webhookServiceClient = {
  async listWebhooks(req: { creatorId?: number } = {}) {
    try {
      const webhooks = await request<any[]>('GET', '/api/v1/webhook');
      return { webhooks };
    } catch (error) {
      console.error('listWebhooks error:', error);
      return { webhooks: [] };
    }
  },

  async getWebhook(req: { id: number }) {
    try {
      const webhook = await request('GET', `/api/v1/webhook/${req.id}`);
      return { webhook };
    } catch (error) {
      console.error('getWebhook error:', error);
      throw error;
    }
  },

  async createWebhook(req: { name: string; url: string }) {
    try {
      const webhook = await request('POST', '/api/v1/webhook', {
        name: req.name,
        url: req.url,
      });
      return { webhook };
    } catch (error) {
      console.error('createWebhook error:', error);
      throw error;
    }
  },

  async updateWebhook(req: { webhook: any; updateMask?: string[] }) {
    try {
      const webhook = await request('PATCH', `/api/v1/webhook/${req.webhook.id}`, {
        name: req.webhook.name,
        url: req.webhook.url,
      });
      return { webhook };
    } catch (error) {
      console.error('updateWebhook error:', error);
      throw error;
    }
  },

  async deleteWebhook(req: { id: number }) {
    try {
      await request('DELETE', `/api/v1/webhook/${req.id}`);
      return {};
    } catch (error) {
      console.error('deleteWebhook error:', error);
      throw error;
    }
  },
};

