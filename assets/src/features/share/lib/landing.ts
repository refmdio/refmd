import { sharesApi } from "@/shared/api";
import { getShareDekEncryptionKey } from "@/shared/lib/crypto/share-dek";
import { ensureShareParticipantDeviceReady } from "./session";

export interface ShareLandingRoot {
  document_token?: string;
  folder_token?: string;
}

interface ShareLandingPayload {
  share: {
    password_protected: boolean;
  };
  root: ShareLandingRoot;
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

async function hasCanonicalShareAccess(root: ShareLandingRoot): Promise<boolean> {
  if (isDocumentRoot(root)) {
    const canonical = await sharesApi.getDocumentBootstrap(root.document_token);
    if ("bootstrap_required" in canonical) return false;
    return !canonical.password_protected || Boolean(getShareDekEncryptionKey(canonical.share_slug));
  }

  if (isFolderRoot(root)) {
    const canonical = await sharesApi.getFolderBootstrap(root.folder_token);
    if ("bootstrap_required" in canonical) return false;
    return !canonical.password_protected || Boolean(getShareDekEncryptionKey(canonical.share_slug));
  }

  throw new Error("unsupported_share_root");
}

export async function resolveShareLanding(shareSlug: string, landing: ShareLandingPayload) {
  const existing = await ensureShareParticipantDeviceReady({
    requiredShareSlug: shareSlug,
  });

  if (existing && (await hasCanonicalShareAccess(landing.root))) {
    return {
      kind: "ready",
      root: landing.root,
    } as const satisfies ShareLandingResolution;
  }

  if (landing.share.password_protected) {
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
