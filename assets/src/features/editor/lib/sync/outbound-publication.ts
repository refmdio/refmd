import * as Y from "yjs";
import { ApiError, publicApi, workspacesApi } from "@/shared/api";
import type { components } from "@/shared/api";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  getDocumentEvents,
  getDocumentRuntime,
  type AppDocuments,
} from "@/shared/lib/document/manager";
import {
  getDocumentPublicationState,
  setDocumentPublicationState,
} from "@/shared/lib/document/publication-state";
import { queryClient } from "@/shared/lib/query/client";
import { getDocumentState } from "../../model/document-state/store";
import type { DocumentState, PublicationState } from "../../model/document-state/types";

type WorkspaceResponse = components["schemas"]["WorkspaceResponse"];
type WorkspacesListResponse = components["schemas"]["WorkspacesListResponse"];
type InitialPublicState = {
  is_published: boolean;
  updated_at: string | null;
  can_sync?: boolean;
};

const inFlight = new Map<string, Promise<void>>();
const rerunRequested = new Set<string>();
const queuedTitleOverrides = new Map<string, string>();
const activeTitleOverrides = new Map<string, string>();
const publicationSyncEpochs = new Map<string, number>();
const pendingWorkspacePublishingChecks = new Map<string, Promise<void>>();

async function contentHash(title: string, content: string): Promise<string> {
  return base64UrlEncode(
    await getCryptoWorker().blake3Hash(new TextEncoder().encode(`${title}\n${content}`)),
  );
}

function getSavedContent(state: DocumentState): string | null {
  if (!state.lastSavedState) return null;

  const saved = new Y.Doc();
  try {
    Y.applyUpdate(saved, state.lastSavedState, "remote");
    return saved.getText("content").toJSON();
  } finally {
    saved.destroy();
  }
}

function getDocumentTitle(documentId: string): string {
  const runtime = getDocumentRuntime() as unknown as Pick<AppDocuments, "getDocumentList">;
  return (
    runtime.getDocumentList().find((document) => document.id === documentId)?.title ?? "Untitled"
  );
}

function getDocumentPublicationSyncPermission(documentId: string): boolean {
  const runtime = getDocumentRuntime() as unknown as Pick<AppDocuments, "getDocumentList">;
  return (
    runtime.getDocumentList().find((document) => document.id === documentId)?.canSyncPublication ===
    true
  );
}

export function setPublicationState(
  documentId: string,
  state: DocumentState,
  publicationState: PublicationState,
  contentHashValue?: string | null,
): void {
  state.publicationState = publicationState;
  state.lastPublicationContentHash = publicationState.isPublished
    ? (contentHashValue ?? null)
    : null;
  setDocumentPublicationState(documentId, {
    ...publicationState,
    contentHash: state.lastPublicationContentHash,
  });
}

export function applyInitialPublicationState(
  documentId: string,
  state: DocumentState,
  publicState: InitialPublicState | undefined,
): void {
  if (!publicState) return;

  state.canSyncPublication = publicState.can_sync === true;
  setPublicationState(
    documentId,
    state,
    {
      isPublished: publicState.is_published,
      updatedAt: publicState.updated_at,
    },
    getDocumentPublicationState(documentId)?.contentHash,
  );
}

export function applyPublicationStatusChanged(
  documentId: string,
  state: DocumentState,
  publicState: { is_published: boolean; updated_at: string | null },
): void {
  if (!publicState.is_published) {
    cancelPendingPublicationSync(documentId);
  }

  setPublicationState(
    documentId,
    state,
    {
      isPublished: publicState.is_published,
      updatedAt: publicState.updated_at,
    },
    getDocumentPublicationState(documentId)?.contentHash,
  );
}

export function queuePublicationAutoSync(documentId: string, state: DocumentState): void {
  queuePublicationSync(documentId, { state, workspaceId: state.workspaceId });
}

export function queuePublicationSaveSync(documentId: string, state: DocumentState): void {
  queuePublicationSync(documentId, { state, workspaceId: state.workspaceId });
}

export function installPublicationRenameAutoSync(): () => void {
  const events = getDocumentEvents();
  const ref = events.on("document-rename", (documentId, _oldTitle, newTitle, isPublished) => {
    queuePublicationSync(documentId, { titleOverride: newTitle, isPublishedHint: isPublished });
  });
  return () => events.offref(ref);
}

function queuePublicationSync(
  documentId: string,
  options: {
    state?: DocumentState;
    titleOverride?: string;
    isPublishedHint?: boolean;
    publicationEpoch?: number;
    workspaceId?: string;
    canSyncPublication?: boolean;
  },
): void {
  const publicationEpoch = options.publicationEpoch ?? getPublicationSyncEpoch(documentId);
  if (publicationEpoch !== getPublicationSyncEpoch(documentId)) return;

  const state = options.state ?? getDocumentState(documentId);
  const workspaceId =
    options.workspaceId ?? state?.workspaceId ?? getDocumentWorkspaceId(documentId);
  if (!state && !options.titleOverride) return;
  if (!workspaceId) return;
  const canSyncPublication =
    options.canSyncPublication ??
    state?.canSyncPublication ??
    getDocumentPublicationSyncPermission(documentId);
  if (!canSyncPublication) return;

  const sharedState = getDocumentPublicationState(documentId);
  const isPublished =
    options.isPublishedHint || state?.publicationState.isPublished || sharedState?.isPublished;
  if (state?.access.kind === "share" || !isPublished) return;

  const publishingStatus = getPublicPublishingStatus(workspaceId);
  if (publishingStatus === "disabled") return;
  if (publishingStatus === "unknown") {
    retryAfterWorkspacePublishingLoaded(documentId, workspaceId, {
      ...options,
      publicationEpoch,
      canSyncPublication,
    });
    return;
  }

  if (options.titleOverride) {
    queuedTitleOverrides.set(documentId, options.titleOverride);
  }

  if (!options.titleOverride && activeTitleOverrides.has(documentId)) {
    rerunRequested.add(documentId);
    return;
  }

  if (inFlight.has(documentId)) {
    rerunRequested.add(documentId);
    return;
  }

  const titleOverride = queuedTitleOverrides.get(documentId) ?? null;
  queuedTitleOverrides.delete(documentId);
  if (titleOverride) {
    activeTitleOverrides.set(documentId, titleOverride);
  }

  const syncEpoch = getPublicationSyncEpoch(documentId);
  const task = syncPublication(documentId, state, titleOverride, syncEpoch, canSyncPublication)
    .catch((error) => {
      if (error instanceof ApiError && error.status === 404) {
        markUnpublished(documentId, state);
      }
      if (
        error instanceof ApiError &&
        error.status === 403 &&
        error.code === "public_publishing_disabled"
      ) {
        cancelPendingPublicationSync(documentId);
        markWorkspacePublicPublishingDisabled(workspaceId);
      }
    })
    .finally(() => {
      const rerunTitleOverride = queuedTitleOverrides.has(documentId)
        ? undefined
        : activeTitleOverrides.get(documentId);

      inFlight.delete(documentId);
      activeTitleOverrides.delete(documentId);

      if (getPublicationSyncEpoch(documentId) !== syncEpoch) {
        rerunRequested.delete(documentId);
        return;
      }

      if (rerunRequested.delete(documentId)) {
        queuePublicationSync(documentId, {
          state: getDocumentState(documentId),
          workspaceId,
          titleOverride: rerunTitleOverride,
          isPublishedHint: rerunTitleOverride ? true : undefined,
          publicationEpoch: syncEpoch,
          canSyncPublication,
        });
      }
    });

  inFlight.set(documentId, task);
}

function getDocumentWorkspaceId(documentId: string): string | null {
  const runtime = getDocumentRuntime() as unknown as Pick<AppDocuments, "getDocumentList">;
  return (
    runtime.getDocumentList().find((document) => document.id === documentId)?.workspaceId ?? null
  );
}

function getPublicPublishingStatus(workspaceId: string): "enabled" | "disabled" | "unknown" {
  const workspace = queryClient.getQueryData<WorkspaceResponse>(["workspace", workspaceId]);
  if (workspace) {
    if (workspace.public_publishing_enabled === true) return "enabled";
    if (workspace.public_publishing_enabled === false) return "disabled";
  }

  const workspaces = queryClient.getQueryData<WorkspacesListResponse>(["workspaces"]);
  const listedWorkspace = workspaces?.workspaces.find((candidate) => candidate.id === workspaceId);
  if (listedWorkspace) {
    if (listedWorkspace.public_publishing_enabled === true) return "enabled";
    if (listedWorkspace.public_publishing_enabled === false) return "disabled";
  }

  return "unknown";
}

function retryAfterWorkspacePublishingLoaded(
  documentId: string,
  workspaceId: string,
  options: {
    state?: DocumentState;
    titleOverride?: string;
    isPublishedHint?: boolean;
    publicationEpoch: number;
    workspaceId?: string;
    canSyncPublication?: boolean;
  },
): void {
  const existing =
    pendingWorkspacePublishingChecks.get(workspaceId) ??
    workspacesApi
      .get(workspaceId)
      .then((workspace) => {
        queryClient.setQueryData(["workspace", workspaceId], workspace);
      })
      .finally(() => {
        pendingWorkspacePublishingChecks.delete(workspaceId);
      });

  pendingWorkspacePublishingChecks.set(workspaceId, existing);
  existing
    .then(() => {
      queuePublicationSync(documentId, { ...options, workspaceId });
    })
    .catch(() => {});
}

function markWorkspacePublicPublishingDisabled(workspaceId: string): void {
  queryClient.setQueryData<WorkspaceResponse | undefined>(["workspace", workspaceId], (current) =>
    current ? { ...current, public_publishing_enabled: false } : current,
  );
  queryClient.setQueryData<WorkspacesListResponse | undefined>(["workspaces"], (current) =>
    current
      ? {
          ...current,
          workspaces: current.workspaces.map((workspace) =>
            workspace.id === workspaceId
              ? { ...workspace, public_publishing_enabled: false }
              : workspace,
          ),
        }
      : current,
  );
  void queryClient.invalidateQueries({ queryKey: ["workspace", workspaceId] });
  void queryClient.invalidateQueries({ queryKey: ["workspaces"] });
}

function markUnpublished(documentId: string, state?: DocumentState): void {
  cancelPendingPublicationSync(documentId);

  if (state) {
    setPublicationState(documentId, state, { isPublished: false, updatedAt: null });
    return;
  }
  setDocumentPublicationState(documentId, {
    isPublished: false,
    updatedAt: null,
    contentHash: null,
  });
}

function getPublicationSyncEpoch(documentId: string): number {
  return publicationSyncEpochs.get(documentId) ?? 0;
}

function bumpPublicationSyncEpoch(documentId: string): void {
  publicationSyncEpochs.set(documentId, getPublicationSyncEpoch(documentId) + 1);
}

function cancelPendingPublicationSync(documentId: string): void {
  bumpPublicationSyncEpoch(documentId);
  rerunRequested.delete(documentId);
  queuedTitleOverrides.delete(documentId);
  activeTitleOverrides.delete(documentId);
}

async function getPublicationContent(
  documentId: string,
  state: DocumentState | undefined,
): Promise<{ content: string; release: () => void } | null> {
  if (state) {
    const content = getSavedContent(state);
    if (content != null) {
      return { content, release: () => {} };
    }
  }

  const runtime = getDocumentRuntime() as unknown as Pick<AppDocuments, "getDocumentById">;
  const doc = await runtime.getDocumentById(documentId);
  if (!doc) return null;

  return { content: doc.text, release: doc.release };
}

async function syncPublication(
  documentId: string,
  state: DocumentState | undefined,
  titleOverride: string | null,
  syncEpoch: number,
  canSyncPublication: boolean,
): Promise<void> {
  const contentRef = await getPublicationContent(documentId, state);
  if (!contentRef) return;

  const { content, release } = contentRef;
  const title = titleOverride ?? getDocumentTitle(documentId);
  const hash = await contentHash(title, content);
  const knownHash =
    state?.lastPublicationContentHash ?? getDocumentPublicationState(documentId)?.contentHash;
  if (hash === knownHash) {
    release();
    return;
  }

  try {
    if (getPublicationSyncEpoch(documentId) !== syncEpoch) return;
    if (state && !state.canSyncPublication) return;
    if (!state && !canSyncPublication) return;
    if (state && !state.publicationState.isPublished) return;
    if (!state && getDocumentPublicationState(documentId)?.isPublished === false) return;

    const result = await publicApi.syncPublicationContent(documentId, {
      title,
      content,
      content_hash: hash,
    });

    if (getPublicationSyncEpoch(documentId) !== syncEpoch) return;
    if (state && !state.canSyncPublication) return;
    if (!state && !canSyncPublication) return;
    if (state && !state.publicationState.isPublished) return;
    if (!state && getDocumentPublicationState(documentId)?.isPublished === false) return;

    if (state) {
      setPublicationState(
        documentId,
        state,
        { isPublished: true, updatedAt: result.updated_at },
        hash,
      );
    } else {
      setDocumentPublicationState(documentId, {
        isPublished: true,
        updatedAt: result.updated_at,
        contentHash: hash,
      });
    }
  } finally {
    release();
  }
}
