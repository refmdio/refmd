import {
  forgetMountTrustAnchor,
  loadMountTrustAnchor,
  mountedShareSessionKey,
  mountTargetTokenHash,
  mountTrustAnchorRequest,
} from "@/entities/mount";
import type { ShareMountDetail } from "@/entities/mount";
import { sharesApi } from "@/shared/api";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import {
  clearShareParticipantSession,
  ensureShareParticipantDeviceReady,
} from "../session/session";
import type { StoredShareParticipantSession } from "@/shared/lib/auth/share-participant-session-store";

type ShareMountLoadOptions = {
  allowPasswordBootstrap?: boolean;
};

type MountedFolderBootstrap = Omit<ShareMountDetail, "mount" | "document"> & {
  mount: { share_id: string };
};

export async function deleteShareMount(mountId: string): Promise<void> {
  await sharesApi.deleteShareMount(mountId);
  await Promise.allSettled([
    forgetMountTrustAnchor(mountId),
    clearShareParticipantSession(mountedShareSessionKey(mountId)),
  ]);
}

export async function moveShareMount(
  mountId: string,
  params: { parentId: string | null; position: number },
) {
  return await sharesApi.updateShareMount(mountId, {
    parent_id: params.parentId,
    position: params.position,
  });
}

export async function getShareMount(
  mountId: string,
  options: ShareMountLoadOptions = {},
): Promise<ShareMountDetail> {
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  await requireMountedShareParticipantSession(anchor);
  const metadata = await sharesApi.getShareMountMetadata(mountId);
  const mount = metadata.mount;
  assertMountMatchesTrustAnchor(anchor, mount);
  if (!mount.target_token) {
    throw new Error("mount_target_token_unavailable");
  }
  if (mount.password_protected && !options.allowPasswordBootstrap) {
    return { mount, document: null };
  }
  if (mount.target_kind === "folder") {
    const folder = (await getShareParticipantCryptoWorker(
      anchor.shareSessionKey,
    ).fetchMountedShareFolderBootstrap({
      mountId,
      folderToken: mount.target_token,
      ...mountTrustAnchorRequest(anchor),
    })) as MountedFolderBootstrap;
    assertBootstrapMountMatchesTrustAnchor(anchor, folder.mount);
    return {
      mount,
      document: null,
      folder: folder.folder ?? null,
      entries: folder.entries ?? [],
    };
  }
  const detail = (await getShareParticipantCryptoWorker(
    anchor.shareSessionKey,
  ).fetchMountedShareDocumentBootstrap({
    mountId,
    documentToken: mount.target_token,
    ...mountTrustAnchorRequest(anchor),
  })) as ShareMountDetail;
  assertBootstrapMountMatchesTrustAnchor(anchor, detail.mount);
  assertDocumentMatchesMountTrustAnchor(anchor.shareId, detail.document);
  return { ...detail, mount };
}

export async function getShareMountEntryDocument(
  mountId: string,
  shareId: string,
  options: ShareMountLoadOptions = {},
): Promise<ShareMountDetail> {
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  await requireMountedShareParticipantSession(anchor);
  const rootDetail = await getShareMount(mountId, options);
  if (rootDetail.mount.password_protected && !options.allowPasswordBootstrap) {
    return rootDetail;
  }
  const documentToken = await findMountedDocumentTokenForShare(
    mountId,
    anchor,
    shareId,
    rootDetail,
  );
  if (!documentToken) {
    throw new Error("mount_document_token_unavailable");
  }
  const detail = await getShareMountDocumentByToken(mountId, documentToken);
  if (detail.document?.share_id !== shareId) {
    throw new Error("mount_share_route_mismatch");
  }
  return detail;
}

async function findMountedDocumentTokenForShare(
  mountId: string,
  anchor: NonNullable<Awaited<ReturnType<typeof loadMountTrustAnchor>>>,
  shareId: string,
  rootDetail: ShareMountDetail,
): Promise<string | null> {
  const queue = [...(rootDetail.entries ?? [])];
  const seenFolderTokens = new Set<string>();

  while (queue.length > 0) {
    const entry = queue.shift();
    if (!entry) continue;
    if (entry.share_id === shareId && entry.doc_type === "document" && entry.document_token) {
      return entry.document_token;
    }
    if (entry.doc_type !== "folder" || !entry.folder_token) continue;
    if (seenFolderTokens.has(entry.folder_token)) continue;
    seenFolderTokens.add(entry.folder_token);

    const folder = (await getShareParticipantCryptoWorker(
      anchor.shareSessionKey,
    ).fetchMountedShareFolderBootstrap({
      mountId,
      folderToken: entry.folder_token,
      ...mountTrustAnchorRequest(anchor),
    })) as MountedFolderBootstrap;
    assertBootstrapMountMatchesTrustAnchor(anchor, folder.mount);
    queue.push(...(folder.entries ?? []));
  }

  return null;
}

export async function getShareMountDocumentByToken(
  mountId: string,
  documentToken: string,
): Promise<ShareMountDetail> {
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  await requireMountedShareParticipantSession(anchor);
  const metadata = await sharesApi.getShareMountMetadata(mountId);
  const mount = metadata.mount;
  assertMountMatchesTrustAnchor(anchor, mount);
  const detail = (await getShareParticipantCryptoWorker(
    anchor.shareSessionKey,
  ).fetchMountedShareDocumentBootstrap({
    mountId,
    documentToken,
    ...mountTrustAnchorRequest(anchor),
  })) as ShareMountDetail;
  assertBootstrapMountMatchesTrustAnchor(anchor, detail.mount);
  assertDocumentMatchesMountTrustAnchor(anchor.shareId, detail.document);
  return { ...detail, mount };
}

function assertMountMatchesTrustAnchor(
  anchor: NonNullable<Awaited<ReturnType<typeof loadMountTrustAnchor>>>,
  mount: ShareMountDetail["mount"],
): void {
  if (mount.share_id !== anchor.shareId) {
    throw new Error("mount_trust_anchor_share_mismatch");
  }
  if (!mount.target_token) {
    throw new Error("mount_target_token_unavailable");
  }
  if (mountTargetTokenHash(mount.target_token) !== anchor.targetTokenHash) {
    throw new Error("mount_trust_anchor_target_mismatch");
  }
}

function assertBootstrapMountMatchesTrustAnchor(
  anchor: NonNullable<Awaited<ReturnType<typeof loadMountTrustAnchor>>>,
  mount: { share_id: string },
): void {
  if (mount.share_id !== anchor.shareId) {
    throw new Error("mount_trust_anchor_share_mismatch");
  }
}

export async function getShareMountForRoute(
  mountId: string,
  shareId: string | null,
  stillCurrent: () => boolean,
  options: ShareMountLoadOptions = {},
): Promise<ShareMountDetail> {
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return shareId
        ? await getShareMountEntryDocument(mountId, shareId, options)
        : await getShareMount(mountId, options);
    } catch (err) {
      lastError = err;
      if (!stillCurrent() || !transientRouteLoadError(err)) break;
      await new Promise((resolve) => window.setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
  throw lastError;
}

export async function getShareMountFolder(mountId: string, folderToken: string) {
  const anchor = await loadMountTrustAnchor(mountId);
  if (!anchor) throw new Error("mount_trust_anchor_unavailable");
  await requireMountedShareParticipantSession(anchor);
  const response = (await getShareParticipantCryptoWorker(
    anchor.shareSessionKey,
  ).fetchMountedShareFolderBootstrap({
    mountId,
    folderToken,
    ...mountTrustAnchorRequest(anchor),
  })) as MountedFolderBootstrap;
  assertBootstrapMountMatchesTrustAnchor(anchor, response.mount);
  return response;
}

async function requireMountedShareParticipantSession(
  anchor: NonNullable<Awaited<ReturnType<typeof loadMountTrustAnchor>>>,
): Promise<StoredShareParticipantSession> {
  const session = await ensureShareParticipantDeviceReady({
    requiredShareSlug: anchor.shareSessionKey,
  });
  if (!session) throw new Error("share_participant_session_unavailable");
  if (session.shareSlug !== anchor.shareSessionKey || session.shareId !== anchor.shareId) {
    throw new Error("mount_share_participant_session_mismatch");
  }
  if (!session.principalId || !session.deviceId || !session.sessionId || !session.signingKeyId) {
    throw new Error("share_participant_session_unavailable");
  }
  return session;
}

function transientRouteLoadError(err: unknown): boolean {
  return err instanceof Error && (err.name === "AbortError" || err instanceof TypeError);
}

function assertDocumentMatchesMountTrustAnchor(
  shareId: string,
  document?: ShareMountDetail["document"],
): void {
  if (!document) return;
  if (document.authorization_share_id !== shareId) {
    throw new Error("mount_trust_anchor_document_mismatch");
  }
}
