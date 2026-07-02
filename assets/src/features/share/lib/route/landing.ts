import { sharesApi } from "@/shared/api";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import {
  ensureShareParticipantDeviceReady,
  readShareSessionTrustAnchor,
  refreshShareSessionTrustAnchorFromBootstrap,
} from "../session/session";
import { getPendingShareParticipantKeypairPrewarm } from "../session/keypair-prewarm";
import { preloadShareDocumentRoute } from "./document";

export interface ShareLandingRoot {
  document_token?: string;
  folder_token?: string;
}

export type ShareLandingPayload = Awaited<ReturnType<typeof sharesApi.getLanding>>;

export type ShareLandingResolution =
  | {
      kind: "ready";
      root: ShareLandingRoot;
    }
  | {
      kind: "password-required";
    }
  | {
      kind: "bootstrap";
      landing: ShareLandingPayload;
    };

function isDocumentRoot(root: ShareLandingRoot): root is { document_token: string } {
  return typeof root.document_token === "string";
}

function isFolderRoot(root: ShareLandingRoot): root is { folder_token: string } {
  return typeof root.folder_token === "string";
}

async function hasCanonicalShareAccess(
  root: ShareLandingRoot,
  shareSlug: string,
): Promise<boolean> {
  const anchor = await readShareSessionTrustAnchor(shareSlug);
  if (!anchor.workspacePinBootstrapHash) return false;
  if (!(await ensureShareParticipantDeviceReady({ requiredShareSlug: shareSlug }))) return false;

  if (isDocumentRoot(root)) {
    const resolved = await preloadShareDocumentRoute(root.document_token, shareSlug);
    return resolved.kind === "ready" && resolved.access.shareSlug === shareSlug;
  }

  if (isFolderRoot(root)) {
    const canonical = await getShareParticipantCryptoWorker(shareSlug).fetchShareFolderBootstrap({
      folderToken: root.folder_token,
      authenticatedWorkspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
    });
    if ("bootstrap_required" in canonical) return false;
    await refreshShareSessionTrustAnchorFromBootstrap(shareSlug, anchor.anchor, canonical);
    return (
      !canonical.password_protected ||
      (await getShareParticipantCryptoWorker(shareSlug).hasShareDekEncryptionKey(shareSlug))
    );
  }

  throw new Error("unsupported_share_root");
}

export async function resolveShareLanding(
  shareSlug: string,
  landing: ShareLandingPayload,
  options: { preferBootstrap?: boolean } = {},
) {
  if (
    options.preferBootstrap &&
    !landing.share.password_protected &&
    getPendingShareParticipantKeypairPrewarm(shareSlug)
  ) {
    return {
      kind: "bootstrap",
      landing,
    } as const satisfies ShareLandingResolution;
  }

  const existing = await ensureShareParticipantDeviceReady({
    requiredShareSlug: shareSlug,
  });

  if (existing && landing.root && (await hasCanonicalShareAccess(landing.root, shareSlug))) {
    return {
      kind: "ready",
      root: landing.root,
    } as const satisfies ShareLandingResolution;
  }

  if (options.preferBootstrap && !landing.share.password_protected) {
    return {
      kind: "bootstrap",
      landing,
    } as const satisfies ShareLandingResolution;
  }

  if (landing.share.password_protected) {
    const anchor = await readShareSessionTrustAnchor(shareSlug);
    if (existing && anchor.workspacePinBootstrapHash) {
      return {
        kind: "bootstrap",
        landing,
      } as const satisfies ShareLandingResolution;
    }

    return {
      kind: "password-required",
    } as const satisfies ShareLandingResolution;
  }

  return {
    kind: "bootstrap",
    landing,
  } as const satisfies ShareLandingResolution;
}

export async function resolveShareLandingRoute(
  shareSlug: string,
  options: { preferBootstrap?: boolean } = {},
) {
  return resolveShareLanding(shareSlug, await sharesApi.getLanding(shareSlug), options);
}
