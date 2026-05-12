export interface Activity {
  id?: number;
  payload?: {
    memoComment?: {
      relatedMemoId?: number;
    };
    versionUpdate?: {
      version?: string;
    };
  };
}

export const ActivityServiceDefinition = {
  name: "ActivityService",
  fullName: "memos.api.v2.ActivityService",
  methods: {},
};
