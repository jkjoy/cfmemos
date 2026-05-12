import { useRef } from "react";
import { resourceServiceClient } from "@/grpcweb";
import * as api from "@/helpers/api";
import { Resource, UpdateResourceRequest } from "@/types/proto/api/v2/resource_service";
import { useTranslate } from "@/utils/i18n";
import store, { useAppSelector } from "../";
import { patchResource, setResources } from "../reducer/resource";
import { useGlobalStore } from "./global";

export const useResourceStore = () => {
  const state = useAppSelector((state) => state.resource);
  const t = useTranslate();
  const globalStore = useGlobalStore();
  const maxUploadSizeMiB = globalStore.state.systemStatus.maxUploadSizeMiB;
  const stateRef = useRef(state);
  const maxUploadSizeMiBRef = useRef(maxUploadSizeMiB);
  const translateRef = useRef(t);
  const apiRef = useRef<ReturnType<typeof buildResourceStoreApi> | null>(null);

  stateRef.current = state;
  maxUploadSizeMiBRef.current = maxUploadSizeMiB;
  translateRef.current = t;

  if (!apiRef.current) {
    apiRef.current = buildResourceStoreApi(stateRef, maxUploadSizeMiBRef, translateRef);
  }

  return apiRef.current!;
};

const buildResourceStoreApi = (
  stateRef: React.MutableRefObject<ReturnType<typeof store.getState>["resource"]>,
  maxUploadSizeMiBRef: React.MutableRefObject<number>,
  translateRef: React.MutableRefObject<ReturnType<typeof useTranslate>>
) => ({
  get state() {
    return stateRef.current;
  },
  getState: () => {
    return store.getState().resource;
  },
  async createResource(resourceCreate: ResourceCreate): Promise<Resource> {
    const { data: resource } = await api.createResource(resourceCreate);
    const resourceList = stateRef.current.resources;
    store.dispatch(setResources([resource, ...resourceList]));
    return resource;
  },
  async createResourceWithBlob(file: File): Promise<Resource> {
    const { name: filename, size } = file;
    if (size > maxUploadSizeMiBRef.current * 1024 * 1024) {
      return Promise.reject(translateRef.current("message.maximum-upload-size-is", { size: maxUploadSizeMiBRef.current }));
    }

    const formData = new FormData();
    formData.append("file", file, filename);
    const { data: resource } = await api.createResourceWithBlob(formData);
    const resourceList = stateRef.current.resources;
    store.dispatch(setResources([resource, ...resourceList]));
    return resource;
  },
  async updateResource(request: UpdateResourceRequest): Promise<Resource> {
    const { resource } = await resourceServiceClient.updateResource(request);
    if (!resource) {
      throw new Error("resource is null");
    }
    store.dispatch(patchResource(resource));
    return resource;
  },
});
