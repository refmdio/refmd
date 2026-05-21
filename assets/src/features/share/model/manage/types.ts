import type { components } from "@/shared/api";

export type ShareListItem = components["schemas"]["ShareListItem"];
export type ShareChildListItem = components["schemas"]["ShareChildListItem"];
export type UpdateShareKeysRequest = components["schemas"]["UpdateShareKeysRequest"];
export type AddFolderShareKeyItem = components["schemas"]["AddFolderShareKeyItem"];
export type ReplaceFolderShareKeyItem = components["schemas"]["ReplaceFolderShareKeyItem"];
export type ShareKeysUpdateDraft =
  | {
      add_keys: AddFolderShareKeyItem[];
      replace_keys?: ReplaceFolderShareKeyItem[];
    }
  | {
      add_keys?: AddFolderShareKeyItem[];
      replace_keys: ReplaceFolderShareKeyItem[];
    };
