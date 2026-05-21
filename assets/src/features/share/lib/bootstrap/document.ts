import { sharesApi } from "@/shared/api";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";
import {
  ensureShareParticipantDeviceReady,
  readShareSessionTrustAnchor,
  refreshShareSessionTrustAnchorFromBootstrap,
  resolveShareSlugForTokenHash,
} from "../session/session";

type CanonicalShareDocumentBootstrap = {
  share_slug: string;
  share_id: string;
  authorization_share_id?: string;
  scope_kind: "document" | "folder";
  scope_id: string;
  permission: "view" | "edit";
  password_protected: boolean;
  share_token_hash: string;
  created_event_hash: string;
  latest_bootstrap_event_hash: string;
  capability_context_hash: string;
  share_capability_secret_commitment: string;
  password_capability_secret_commitment: string;
  document_id: string;
  workspace_id: string;
  encrypted_title: string | null;
  encrypted_title_nonce: string | null;
  encrypted_title_key_version: number | null;
  key_version: number;
  encrypted_key_refs: string[];
  workspace_pin_bootstrap: unknown;
  workspace_key_directory_checkpoint: unknown;
  verification_directory: unknown;
};

export type SharedDocumentBootstrapResult =
  | {
      kind: "bootstrap-required";
      shareSlug: string;
    }
  | {
      kind: "ready";
      response: CanonicalShareDocumentBootstrap;
      session: NonNullable<Awaited<ReturnType<typeof ensureShareParticipantDeviceReady>>>;
      trustAnchor: Awaited<ReturnType<typeof readShareSessionTrustAnchor>>;
    };

let activeShareSocketSlug: string | null = null;

export function clearActiveShareSocketSlug(): void {
  activeShareSocketSlug = null;
}

export async function resolveSharedDocumentBootstrap(
  documentToken: string,
): Promise<SharedDocumentBootstrapResult> {
  const requirement = await sharesApi.getDocumentBootstrapRequirement(documentToken);
  if (!("bootstrap_required" in requirement)) {
    throw new Error("share_bootstrap_requirement_invalid");
  }
  const requirementShareSlug = await resolveShareSlugForTokenHash(requirement.share_token_hash);

  if (requirement.bootstrap_required) {
    if (!requirementShareSlug) {
      throw new Error("share_session_required");
    }
    const session = await ensureShareParticipantDeviceReady({
      requiredShareSlug: requirementShareSlug,
    });
    if (
      !session ||
      !(await getShareParticipantCryptoWorker(requirementShareSlug).hasShareDekEncryptionKey(
        requirementShareSlug,
      ))
    ) {
      return {
        kind: "bootstrap-required",
        shareSlug: requirementShareSlug,
      };
    }
  }

  if (!requirementShareSlug) {
    throw new Error("share_session_required");
  }

  const anchor = await readShareSessionTrustAnchor(requirementShareSlug);
  if (!anchor.workspacePinBootstrapHash) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }

  const session = await ensureShareParticipantDeviceReady({
    requiredShareSlug: requirementShareSlug,
  });

  if (!session) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }

  const response = await getShareParticipantCryptoWorker(
    requirementShareSlug,
  ).fetchShareDocumentBootstrap({
    documentToken,
    authenticatedWorkspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
  });
  if ("bootstrap_required" in response) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }
  const canonicalResponse = normalizeDocumentBootstrapResponse(response, requirementShareSlug);
  const refreshedAnchor = await refreshShareSessionTrustAnchorFromBootstrap(
    requirementShareSlug,
    anchor.anchor,
    canonicalResponse,
  );

  if (
    !(await getShareParticipantCryptoWorker(requirementShareSlug).hasShareDekEncryptionKey(
      requirementShareSlug,
    ))
  ) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }

  if (activeShareSocketSlug !== requirementShareSlug) {
    resetPhoenixConnection("share");
    activeShareSocketSlug = requirementShareSlug;
  }

  return {
    kind: "ready",
    response: canonicalResponse,
    session,
    trustAnchor: {
      ...anchor,
      anchor: refreshedAnchor,
      workspacePinBootstrapHash:
        refreshedAnchor?.workspacePinBootstrapHash ?? anchor.workspacePinBootstrapHash,
      shareCapabilitySecretCommitment:
        refreshedAnchor?.shareCapabilitySecretCommitment ?? anchor.shareCapabilitySecretCommitment,
      passwordCapabilitySecretCommitment:
        refreshedAnchor?.passwordCapabilitySecretCommitment ??
        anchor.passwordCapabilitySecretCommitment,
      capabilityContextHash: refreshedAnchor?.capabilityContextHash ?? anchor.capabilityContextHash,
    },
  };
}

function normalizeDocumentBootstrapResponse(
  response: Record<string, unknown>,
  shareSlug: string,
): CanonicalShareDocumentBootstrap {
  return {
    share_slug: shareSlug,
    share_id: stringValue(response.share_id, "share_id_invalid"),
    authorization_share_id: optionalString(response.authorization_share_id),
    scope_kind: scopeKindValue(response.scope_kind),
    scope_id: stringValue(response.scope_id, "scope_id_invalid"),
    permission: permissionValue(response.permission),
    password_protected: booleanValue(response.password_protected, "password_protected_invalid"),
    share_token_hash: stringValue(response.share_token_hash, "share_token_hash_invalid"),
    created_event_hash: stringValue(response.created_event_hash, "created_event_hash_invalid"),
    latest_bootstrap_event_hash: stringValue(
      response.latest_bootstrap_event_hash,
      "latest_bootstrap_event_hash_invalid",
    ),
    capability_context_hash: stringValue(
      response.capability_context_hash,
      "capability_context_hash_invalid",
    ),
    share_capability_secret_commitment: stringValue(
      response.share_capability_secret_commitment,
      "share_capability_secret_commitment_invalid",
    ),
    password_capability_secret_commitment: stringValue(
      response.password_capability_secret_commitment,
      "password_capability_secret_commitment_invalid",
    ),
    document_id: stringValue(response.document_id, "document_id_invalid"),
    workspace_id: stringValue(response.workspace_id, "workspace_id_invalid"),
    encrypted_title: nullableString(response.encrypted_title, "encrypted_title_invalid"),
    encrypted_title_nonce: nullableString(
      response.encrypted_title_nonce,
      "encrypted_title_nonce_invalid",
    ),
    encrypted_title_key_version: nullableNumber(
      response.encrypted_title_key_version,
      "encrypted_title_key_version_invalid",
    ),
    key_version: numberValue(response.key_version, "key_version_invalid"),
    encrypted_key_refs: stringArrayValue(response.encrypted_key_refs, "encrypted_key_refs_invalid"),
    workspace_pin_bootstrap: response.workspace_pin_bootstrap,
    workspace_key_directory_checkpoint: response.workspace_key_directory_checkpoint,
    verification_directory: response.verification_directory,
  };
}

function stringValue(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function nullableString(value: unknown, code: string): string | null {
  if (value === null) return null;
  return stringValue(value, code);
}

function numberValue(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(code);
  return value;
}

function nullableNumber(value: unknown, code: string): number | null {
  if (value === null) return null;
  return numberValue(value, code);
}

function booleanValue(value: unknown, code: string): boolean {
  if (typeof value !== "boolean") throw new Error(code);
  return value;
}

function stringArrayValue(value: unknown, code: string): string[] {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(code);
  }
  return value;
}

function permissionValue(value: unknown): "view" | "edit" {
  if (value === "view" || value === "edit") return value;
  throw new Error("permission_invalid");
}

function scopeKindValue(value: unknown): "document" | "folder" {
  if (value === "document" || value === "folder") return value;
  throw new Error("scope_kind_invalid");
}
