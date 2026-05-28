import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { documentsApi } from "@/shared/api";
import type { DocumentResponse } from "@/entities/document";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildDocumentWriteStateKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/document-admission-events";
import { getDocumentEvents } from "@/shared/lib/document/manager";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

export async function archiveDocument(
  document: DocumentResponse,
  documents: DocumentResponse[],
): Promise<void> {
  const affected = affectedSubtreeDocuments(document, documents).filter(
    (doc) => currentWriteState(doc) !== "archived",
  );
  const { append, previousCheckpoint } = await buildWriteStateAppend(
    document.workspace_id,
    affected,
    "archive",
  );
  await documentsApi.archive(document.id, {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
  });
  await advanceWriteStatePin(document.workspace_id, append, previousCheckpoint);
}

export async function unarchiveDocument(
  document: DocumentResponse,
  documents: DocumentResponse[],
): Promise<void> {
  const affected = affectedSubtreeDocuments(document, documents).filter((doc) => !!doc.archived_at);
  const { append, previousCheckpoint } = await buildWriteStateAppend(
    document.workspace_id,
    affected,
    "unarchive",
  );
  await documentsApi.unarchive(document.id, {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
  });
  await advanceWriteStatePin(document.workspace_id, append, previousCheckpoint);
}

export async function deleteDocument(documentId: string): Promise<void> {
  await documentsApi.delete(documentId);
  getDocumentEvents().notifyDocumentDelete(documentId);
}

async function buildWriteStateAppend(
  workspaceId: string,
  documents: DocumentResponse[],
  reason: "archive" | "unarchive",
) {
  const auth = authState();
  const currentDevice = deviceState();
  if (!cryptoWorkerReady() || !auth || !currentDevice?.deviceId) {
    throw new Error("document_write_state_signer_unavailable");
  }

  const directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: workspaceId,
    popDeviceId: currentDevice.deviceId,
  });

  const append = await buildDocumentWriteStateKeyDirectoryAppend({
    workspaceId,
    actorUserId: auth.user.id,
    actorDeviceId: currentDevice.deviceId,
    checkpointEnvelope: directory.checkpoint,
    changes: documents.map((document) => ({
      documentId: document.id,
      previousWriteState: reason === "archive" ? currentWriteState(document) : "archived",
      writeState: reason === "archive" ? "archived" : "writable",
    })),
    reason,
  });

  return { append, previousCheckpoint: directory.checkpoint };
}

async function advanceWriteStatePin(
  workspaceId: string,
  append: Awaited<ReturnType<typeof buildDocumentWriteStateKeyDirectoryAppend>>,
  previousCheckpoint: Awaited<ReturnType<typeof fetchVerifiedKeyDirectory>>["checkpoint"],
): Promise<void> {
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope: append.checkpoint,
    checkpointAncestry: [previousCheckpoint],
    eventAncestry: append.events,
  });
}

function currentWriteState(
  document: DocumentResponse,
): "writable" | "read_only" | "archived" | "write_disabled" {
  if (document.archived_at) return "archived";
  return document.write_state ?? "writable";
}

function affectedSubtreeDocuments(
  root: DocumentResponse,
  documents: DocumentResponse[],
): DocumentResponse[] {
  const childrenByParent = new Map<string | null, DocumentResponse[]>();
  for (const document of documents) {
    const parentId = document.parent_id ?? null;
    childrenByParent.set(parentId, [...(childrenByParent.get(parentId) ?? []), document]);
  }

  const affected: DocumentResponse[] = [];
  const visit = (document: DocumentResponse) => {
    affected.push(document);
    for (const child of childrenByParent.get(document.id) ?? []) visit(child);
  };
  visit(root);
  return affected;
}
