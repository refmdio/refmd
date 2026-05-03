import { sharesApi } from "@/shared/api";
import { getShareDekEncryptionKey } from "@/shared/lib/crypto/share-dek";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";
import { ensureShareParticipantDeviceReady } from "./session";

interface CanonicalShareDocumentBootstrap {
  document_id: string;
  title: string | null;
  encrypted_title: string | null;
  encrypted_title_nonce: string | null;
  encrypted_title_key_version: number | null;
  encrypted_dek: string;
  key_version: number;
  nonce: string | null;
  password_protected: boolean;
  permission: "view" | "edit";
  share_id: string;
  share_slug: string;
  verification_directory: {
    workspace_devices: Record<string, never>[];
    share_participant_devices: Record<string, never>[];
  };
  workspace_id: string;
}

export type SharedDocumentBootstrapResult =
  | {
      kind: "bootstrap-required";
      shareSlug: string;
    }
  | {
      kind: "ready";
      response: CanonicalShareDocumentBootstrap;
      session: NonNullable<Awaited<ReturnType<typeof ensureShareParticipantDeviceReady>>>;
    };

let activeShareSocketSlug: string | null = null;

export function clearActiveShareSocketSlug(): void {
  activeShareSocketSlug = null;
}

export async function resolveSharedDocumentBootstrap(
  documentToken: string,
): Promise<SharedDocumentBootstrapResult> {
  const response = await sharesApi.getDocumentBootstrap(documentToken);
  if ("bootstrap_required" in response) {
    return {
      kind: "bootstrap-required",
      shareSlug: response.share_slug,
    };
  }

  const session = await ensureShareParticipantDeviceReady({
    requiredShareSlug: response.share_slug,
  });

  if (!session) {
    return {
      kind: "bootstrap-required",
      shareSlug: response.share_slug,
    };
  }

  if (response.password_protected && !getShareDekEncryptionKey(response.share_slug)) {
    return {
      kind: "bootstrap-required",
      shareSlug: response.share_slug,
    };
  }

  if (activeShareSocketSlug !== response.share_slug) {
    resetPhoenixConnection("share");
    activeShareSocketSlug = response.share_slug;
  }

  return {
    kind: "ready",
    response: response as CanonicalShareDocumentBootstrap,
    session,
  };
}
