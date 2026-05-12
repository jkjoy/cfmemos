declare module "@/store/authStore" {
  interface AuthStoreUser {
    id?: number;
    username?: string;
    nickname?: string;
    role?: string;
    is_admin?: number | boolean;
  }

  interface AuthStoreState {
    user: AuthStoreUser | null;
    token: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    setAuth: (user: AuthStoreUser | null, token: string | null) => void;
    setUser: (user: AuthStoreUser | null) => void;
    logout: () => void;
    setLoading: (isLoading: boolean) => void;
    isAdmin: () => boolean;
    initialize: () => void;
  }

  export const useAuthStore: {
    (): AuthStoreState;
    <T>(selector: (state: AuthStoreState) => T): T;
  };
}

declare module "@/api/users" {
  interface UserApiAuthPayload {
    username: string;
    password: string;
    nickname?: string;
    email?: string;
  }

  interface UserApiAuthResponse {
    user?: Record<string, any>;
    token?: string;
    error?: string;
    message?: string;
  }

  export const userAPI: {
    login: (credentials: UserApiAuthPayload) => Promise<UserApiAuthResponse>;
    register: (data: UserApiAuthPayload) => Promise<UserApiAuthResponse>;
    logout: () => Promise<any>;
    list: (params?: Record<string, any>) => Promise<any>;
    get: (id?: string | number) => Promise<any>;
    update: (id: string | number, data: Record<string, any>) => Promise<any>;
    changePassword: (id: string | number, data: Record<string, any>) => Promise<any>;
    delete: (id: string | number) => Promise<any>;
  };
}

declare module "textarea-caret" {
  function getCaretCoordinates(element: HTMLTextAreaElement, position: number): { left: number; top: number; height: number };
  export default getCaretCoordinates;
}
