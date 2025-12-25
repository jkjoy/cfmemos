import { RowStatus } from "./common";

export enum Visibility {
  VISIBILITY_UNSPECIFIED = 0,
  PRIVATE = 1,
  PROTECTED = 2,
  PUBLIC = 3,
}

export interface Memo {
  id: number;
  rowStatus: RowStatus;
  creatorId: number;
  createdTs: number;
  updatedTs: number;
  content: string;
  visibility: Visibility;
  pinned: boolean;
}

export const MemoServiceDefinition = {
  name: "MemoService",
  fullName: "memos.api.v2.MemoService",
  methods: {},
};
