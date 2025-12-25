// Type definitions for user_service protobuf

export enum User_Role {
  ROLE_UNSPECIFIED = 0,
  HOST = 1,
  ADMIN = 2,
  USER = 3,
}

export interface User {
  id: number;
  name: string;
  username: string;
  email: string;
  nickname: string;
  avatarUrl: string;
  role: User_Role;
  createdTime?: string;
  updatedTime?: string;
  rowStatus: number;
}

export interface UserSetting {
  name: string;
  locale: string;
  appearance: string;
  memoVisibility: string;
  telegramUserId?: string;
}

// ts-proto compatible helpers
export const User = {
  fromPartial(object: Partial<User>): User {
    return {
      id: object.id ?? 0,
      name: object.name ?? "",
      username: object.username ?? "",
      email: object.email ?? "",
      nickname: object.nickname ?? "",
      avatarUrl: object.avatarUrl ?? "",
      role: object.role ?? User_Role.ROLE_UNSPECIFIED,
      createdTime: object.createdTime,
      updatedTime: object.updatedTime,
      rowStatus: object.rowStatus ?? 0,
    };
  },
};

export const UserSetting = {
  fromPartial(object: Partial<UserSetting>): UserSetting {
    return {
      name: object.name ?? "",
      locale: object.locale ?? "en",
      appearance: object.appearance ?? "auto",
      memoVisibility: object.memoVisibility ?? "PRIVATE",
      telegramUserId: object.telegramUserId ?? "",
    };
  },
};

export const UserServiceDefinition = {
  name: "UserService",
  fullName: "memos.api.v2.UserService",
  methods: {},
};
