export interface Resource {
  id: number;
  name: string;
  uid: string;
  createdTime?: string;
  filename: string;
  externalLink: string;
  type: string;
  size: number;
  memo?: any;
  memoId?: number;
}

// ts-proto compatible helpers
export const Resource = {
  fromPartial(object: Partial<Resource>): Resource {
    return {
      id: object.id ?? 0,
      name: object.name ?? "",
      uid: object.uid ?? "",
      createdTime: object.createdTime,
      filename: object.filename ?? "",
      externalLink: object.externalLink ?? "",
      type: object.type ?? "",
      size: object.size ?? 0,
      memo: object.memo,
      memoId: object.memoId,
    };
  },
};

export const ResourceServiceDefinition = {
  name: "ResourceService",
  fullName: "memos.api.v2.ResourceService",
  methods: {},
};
