import type * as Y from "yjs";

export interface CacheableDocumentState {
  yDoc: Y.Doc;
  keyVersion: number;
  activeSnapshotId: string | null;
  latestVersion: number;
  confirmedClocks: Record<string, number>;
  lastSavedState: Uint8Array | null;
  initialized: boolean;
  _cachedConfirmedStateVector?: Uint8Array | null;
}

export interface RecoveredDocumentState {
  yDoc: Y.Doc;
  confirmedBaseState: Uint8Array | null;
  confirmedStateVector: Uint8Array | null;
  confirmedSnapshotId: string;
  confirmedClocks: Record<string, number>;
  confirmedVersion: number;
  keyVersion: number;
  workspaceId: string;
  hasPendingChanges: boolean;
}
