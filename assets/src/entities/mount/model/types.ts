import type { components } from "@/shared/api";

export type ShareMount = components["schemas"]["ShareMountResponse"];
export type ShareMountLookupItem = components["schemas"]["ShareMountLookupItem"];
export type ShareMountDetail = components["schemas"]["ShareMountDetailResponse"];
export type ShareMountAdmission = components["schemas"]["MountedShareAdmission"];
export type ShareTreeEntry = components["schemas"]["ShareTreeEntry"];
export type MountedShareTreeEntry = ShareTreeEntry & { label: string };
