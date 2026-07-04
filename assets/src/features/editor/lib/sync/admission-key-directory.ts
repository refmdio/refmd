import { deviceState } from "@/entities/session";
import {
  fetchVerifiedKeyDirectory,
  fetchVerifiedKeyDirectoryFromTrustedCheckpoint,
} from "@/shared/lib/key-directory/fetch";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import type { DocumentState } from "../../model/document-state/types";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { rememberShareWorkspaceCheckpoint } from "./outbound-admission";
import { getLocalDeviceId } from "./share-identity";
import { recordSyncPerf } from "./perf";

export async function refreshAdmissionKeyDirectory(
  state: DocumentState,
  documentId: string,
  params?: { trustedCheckpointEnvelope?: SignedKeyDirectoryEnvelope },
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
  const fetchParams = {
    scopeKind: "workspace" as const,
    scopeId: state.workspaceId,
    popDeviceId,
    popScope: accessKind === "share" ? ("share" as const) : ("user" as const),
    popWorker: shareWorker,
  };
  const directory = params?.trustedCheckpointEnvelope
    ? await fetchVerifiedKeyDirectoryFromTrustedCheckpoint({
        ...fetchParams,
        trustedCheckpointEnvelope:
          params.trustedCheckpointEnvelope as unknown as KeyDirectoryEnvelope,
      })
    : await fetchVerifiedKeyDirectory(fetchParams);
  rememberShareWorkspaceCheckpoint(state.access, directory.checkpoint);
  recordSyncPerf("admission_key_directory_refresh_ready", {
    documentId,
    accessKind,
    workspaceId: state.workspaceId,
  });
}

export function createAdmissionKeyDirectoryRefresh(
  state: DocumentState,
  documentId: string,
): (params?: { trustedCheckpointEnvelope?: SignedKeyDirectoryEnvelope }) => Promise<void> {
  return (params) => refreshAdmissionKeyDirectory(state, documentId, params);
}
