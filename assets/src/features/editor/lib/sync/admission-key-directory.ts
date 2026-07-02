import { deviceState } from "@/entities/session";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import type { DocumentState } from "../../model/document-state/types";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { rememberShareWorkspaceCheckpoint } from "./outbound-admission";
import { getLocalDeviceId } from "./share-identity";
import { recordSyncPerf } from "./perf";

export async function refreshAdmissionKeyDirectory(
  state: DocumentState,
  documentId: string,
): Promise<void> {
  const accessKind = state.access.kind;
  const shareWorker = accessKind === "share" ? getDocumentCryptoWorker(state) : undefined;
  const popDeviceId =
    getLocalDeviceId(state) ??
    deviceState()?.deviceId ??
    (shareWorker ? await shareWorker.getDeviceId() : null);

  if (!popDeviceId) {
    throw new Error("admission_key_directory_refresh_device_unavailable");
  }

  recordSyncPerf("admission_key_directory_refresh_start", {
    documentId,
    accessKind,
    workspaceId: state.workspaceId,
  });
  const directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: state.workspaceId,
    popDeviceId,
    popScope: accessKind === "share" ? "share" : "user",
    popWorker: shareWorker,
  });
  rememberShareWorkspaceCheckpoint(state.access, directory.checkpoint);
  recordSyncPerf("admission_key_directory_refresh_ready", {
    documentId,
    accessKind,
    workspaceId: state.workspaceId,
  });
}
