import { sharesApi } from "@/shared/api";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import {
  ensureShareParticipantDeviceReady,
  readShareSessionTrustAnchor,
  refreshShareSessionTrustAnchorFromBootstrap,
} from "../session/session";

export interface ShareLandingRoot {
  document_token?: string;
  folder_token?: string;
}

interface ShareLandingPayload {
  share: {
    permission: "view" | "edit";
    password_protected: boolean;
  };
  root?: ShareLandingRoot | null;
}

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
    const canonical = await getShareParticipantCryptoWorker(shareSlug).fetchShareDocumentBootstrap({
      documentToken: root.document_token,
      authenticatedWorkspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
    });
    if ("bootstrap_required" in canonical) return false;
    await refreshShareSessionTrustAnchorFromBootstrap(shareSlug, anchor.anchor, canonical);
    return (
      !canonical.password_protected ||
      (await getShareParticipantCryptoWorker(shareSlug).hasShareDekEncryptionKey(shareSlug))
    );
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

export async function resolveShareLanding(shareSlug: string, landing: ShareLandingPayload) {
  const existing = await ensureShareParticipantDeviceReady({
    requiredShareSlug: shareSlug,
  });

  if (existing && landing.root && (await hasCanonicalShareAccess(landing.root, shareSlug))) {
    return {
      kind: "ready",
      root: landing.root,
    } as const satisfies ShareLandingResolution;
  }

  if (landing.share.password_protected) {
    const anchor = await readShareSessionTrustAnchor(shareSlug);
    if (existing && anchor.workspacePinBootstrapHash) {
      return {
        kind: "bootstrap",
      } as const satisfies ShareLandingResolution;
    }

    return {
      kind: "password-required",
    } as const satisfies ShareLandingResolution;
  }

  return {
    kind: "bootstrap",
  } as const satisfies ShareLandingResolution;
}

export async function resolveShareLandingRoute(shareSlug: string) {
  return resolveShareLanding(shareSlug, await sharesApi.getLanding(shareSlug));
}
