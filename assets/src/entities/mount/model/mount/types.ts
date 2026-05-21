import type { components } from "@/shared/api";

export type ShareMount = components["schemas"]["ShareMountListItem"] & { workspace_id: string };
export type ShareMountMetadata = components["schemas"]["ShareMountResponse"];
export type ShareMountBootstrapMount = components["schemas"]["ShareMountBootstrapMountSummary"];
export type ShareLinkMount = components["schemas"]["ShareLinkMountListItem"];
export type ShareMountDocument = Omit<
  components["schemas"]["MountedShareDocument"],
  "encrypted_dek" | "nonce"
> & {
  encrypted_key_refs: string[];
};
export type ShareTreeEntry = Omit<
  components["schemas"]["MountedShareTreeEntry"],
  "encrypted_dek" | "nonce"
> & {
  encrypted_key_refs: string[];
};
export type ShareMountDetail = {
  mount: ShareMountMetadata;
  document: ShareMountDocument | null;
  folder?: ShareTreeEntry | null;
  entries?: ShareTreeEntry[];
};
export type MountedShareTreeEntry = ShareTreeEntry & { label: string };
