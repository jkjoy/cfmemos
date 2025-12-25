export enum Inbox_Status {
  STATUS_UNSPECIFIED = 0,
  UNREAD = 1,
  ARCHIVED = 2,
}

export enum Inbox_Type {
  TYPE_UNSPECIFIED = 0,
  TYPE_MEMO_COMMENT = 1,
  TYPE_VERSION_UPDATE = 2,
}

export interface Inbox {
  name: string;
  sender: string;
  receiver: string;
  status: Inbox_Status;
  createdTime?: string;
  type: Inbox_Type;
  activityId?: number;
}

export const InboxServiceDefinition = {
  name: "InboxService",
  fullName: "memos.api.v2.InboxService",
  methods: {},
};
