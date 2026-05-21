import { authState, deviceState } from "@/entities/session";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export interface MountTrustAnchor {
  mountId: string;
  shareId: string;
  targetKind: "document" | "folder";
  shareSessionKey: string;
  targetTokenHash: string;
  workspacePinBootstrapHash: string;
  targetTitle?: string | null;
  userId: string;
  deviceId: string;
  createdAtMs: number;
}

interface MountTrustAnchorRecord {
  protocol: "refmd.mount-trust-anchor";
  version: 1;
  mount_id: string;
  share_id: string;
  target_kind: "document" | "folder";
  target_token_hash: string;
  workspace_pin_bootstrap_hash: string;
  share_session_key: string;
  authenticated_source_kind: "url-fragment";
  mount_owner_user_id: string;
  mount_owner_device_id: string;
  created_at_ms: number;
  target_title: string;
}

type MountTrustAnchorAadRecord = Pick<
  MountTrustAnchorRecord,
  | "protocol"
  | "version"
  | "mount_id"
  | "share_id"
  | "target_kind"
  | "target_token_hash"
  | "workspace_pin_bootstrap_hash"
  | "share_session_key"
  | "authenticated_source_kind"
  | "mount_owner_user_id"
  | "mount_owner_device_id"
  | "created_at_ms"
>;

function mountTrustAnchorAadRecord(record: MountTrustAnchorRecord): MountTrustAnchorAadRecord {
  return {
    protocol: record.protocol,
    version: record.version,
    mount_id: record.mount_id,
    share_id: record.share_id,
    target_kind: record.target_kind,
    target_token_hash: record.target_token_hash,
    workspace_pin_bootstrap_hash: record.workspace_pin_bootstrap_hash,
    share_session_key: record.share_session_key,
    authenticated_source_kind: record.authenticated_source_kind,
    mount_owner_user_id: record.mount_owner_user_id,
    mount_owner_device_id: record.mount_owner_device_id,
    created_at_ms: record.created_at_ms,
  };
}

function recordFromAnchor(anchor: MountTrustAnchor): MountTrustAnchorRecord {
  return {
    protocol: "refmd.mount-trust-anchor",
    version: 1,
    mount_id: anchor.mountId,
    share_id: anchor.shareId,
    target_kind: anchor.targetKind,
    target_token_hash: anchor.targetTokenHash,
    workspace_pin_bootstrap_hash: anchor.workspacePinBootstrapHash,
    share_session_key: anchor.shareSessionKey,
    authenticated_source_kind: "url-fragment",
    mount_owner_user_id: anchor.userId,
    mount_owner_device_id: anchor.deviceId,
    created_at_ms: anchor.createdAtMs,
    target_title: anchor.targetTitle ?? "",
  };
}

function anchorFromRecord(record: MountTrustAnchorRecord): MountTrustAnchor {
  return {
    mountId: record.mount_id,
    shareId: record.share_id,
    targetKind: record.target_kind,
    shareSessionKey: record.share_session_key,
    targetTokenHash: record.target_token_hash,
    workspacePinBootstrapHash: record.workspace_pin_bootstrap_hash,
    targetTitle: record.target_title || null,
    userId: record.mount_owner_user_id,
    deviceId: record.mount_owner_device_id,
    createdAtMs: record.created_at_ms,
  };
}

export function readWorkspacePinBootstrapHashFromLocation(): string | null {
  const hash = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  if (!hash) return null;
  const params = new URLSearchParams(hash);
  const value = params.get("wpb");
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

export function readShareSlugFromLocation(): string | null {
  const hash = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  if (!hash) return null;
  const value = new URLSearchParams(hash).get("s");
  if (!value || !/^[A-Za-z0-9_-]{22}$/.test(value)) return null;

  try {
    const slug = base64UrlDecode(value);
    return slug.length === 16 ? value : null;
  } catch {
    return null;
  }
}

export function readShareUrlFragmentFromLocation(): string | null {
  const hash = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  if (!hash) return null;
  if (!/(^|&)cap=[A-Za-z0-9_-]{43}(&|$)/.test(hash)) return null;
  return hash;
}

export function mountTargetTokenHash(targetToken: string): string {
  return blake3Base64Url(base64UrlDecode(targetToken));
}

async function persistMountTrustAnchor(anchor: MountTrustAnchor): Promise<void> {
  const auth = authState();
  const device = deviceState();
  if (!auth?.user.id || !device?.deviceId) throw new Error("mount_trust_anchor_owner_unavailable");

  const worker = getCryptoWorker();
  if (!(await worker.loadStoredDsk())) throw new Error("mount_trust_anchor_dsk_unavailable");

  if (anchor.userId !== auth.user.id || anchor.deviceId !== device.deviceId) {
    throw new Error("mount_trust_anchor_owner_mismatch");
  }
  const record = recordFromAnchor(anchor);
  const aad = mountTrustAnchorAadRecord(record);

  await worker.storeMountTrustAnchorWithDsk({
    mountId: anchor.mountId,
    plaintext: canonicalizeStrictBytes(record as unknown as StrictJsonValue),
    aadRecord: aad,
  });
}

export async function rememberMountTrustAnchor(params: {
  mountId: string;
  shareId: string;
  shareSessionKey: string;
  targetToken: string;
  targetKind: "document" | "folder";
  targetTitle?: string | null;
  workspacePinBootstrapHash: string;
}): Promise<void> {
  const auth = authState();
  const device = deviceState();
  if (!auth?.user.id || !device?.deviceId) throw new Error("mount_trust_anchor_owner_unavailable");

  const anchor: MountTrustAnchor = {
    mountId: params.mountId,
    shareId: params.shareId,
    targetKind: params.targetKind,
    shareSessionKey: params.shareSessionKey,
    targetTokenHash: mountTargetTokenHash(params.targetToken),
    workspacePinBootstrapHash: params.workspacePinBootstrapHash,
    targetTitle: params.targetTitle ?? null,
    userId: auth.user.id,
    deviceId: device.deviceId,
    createdAtMs: Date.now(),
  };
  await persistMountTrustAnchor(anchor);
}

export async function forgetMountTrustAnchor(mountId: string): Promise<void> {
  await getCryptoWorker().deleteMountTrustAnchorWithDsk(mountId);
}

export async function loadMountTrustAnchor(
  mountId: string,
  expectedShareId?: string | null,
  expectedTargetToken?: string | null,
): Promise<MountTrustAnchor | null> {
  const auth = authState();
  const device = deviceState();
  if (!auth?.user.id || !device?.deviceId) return null;

  const validateRecord = (record: MountTrustAnchorRecord | null): MountTrustAnchor | null => {
    if (!record) return null;
    const expectedKeys = [
      "authenticated_source_kind",
      "created_at_ms",
      "mount_id",
      "mount_owner_device_id",
      "mount_owner_user_id",
      "protocol",
      "share_id",
      "share_session_key",
      "target_kind",
      "target_title",
      "target_token_hash",
      "version",
      "workspace_pin_bootstrap_hash",
    ];
    if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expectedKeys)) return null;
    if (record.protocol !== "refmd.mount-trust-anchor" || record.version !== 1) return null;
    if (record.mount_id !== mountId) return null;
    if (expectedShareId && record.share_id !== expectedShareId) return null;
    if (record.target_kind !== "document" && record.target_kind !== "folder") return null;
    if (record.share_session_key !== mountedShareSessionKey(mountId)) return null;
    if (record.authenticated_source_kind !== "url-fragment") return null;
    if (
      record.target_title != null &&
      (typeof record.target_title !== "string" || record.target_title.length > 512)
    ) {
      return null;
    }
    if (
      expectedTargetToken &&
      record.target_token_hash !== mountTargetTokenHash(expectedTargetToken)
    ) {
      return null;
    }
    if (
      record.mount_owner_user_id !== auth.user.id ||
      record.mount_owner_device_id !== device.deviceId
    ) {
      return null;
    }
    return anchorFromRecord(record);
  };

  const worker = getCryptoWorker();
  if (!(await worker.loadStoredDsk())) return null;

  try {
    const stored = await worker.loadMountTrustAnchorWithDsk(mountId);
    if (!stored) return null;
    const record = JSON.parse(new TextDecoder().decode(stored)) as MountTrustAnchorRecord;
    const aad = mountTrustAnchorAadRecord(record);
    if (aad.mount_id !== mountId) return null;
    if (expectedShareId && aad.share_id !== expectedShareId) return null;
    if (
      expectedTargetToken &&
      aad.target_token_hash !== mountTargetTokenHash(expectedTargetToken)
    ) {
      return null;
    }
    return validateRecord(record);
  } catch {
    return null;
  }
}

export async function loadMountTrustAnchorHash(
  mountId: string,
  expectedShareId?: string | null,
  expectedTargetToken?: string | null,
): Promise<string | null> {
  const anchor = await loadMountTrustAnchor(mountId, expectedShareId, expectedTargetToken);
  return anchor?.workspacePinBootstrapHash ?? null;
}

export function mountTrustAnchorRequest(anchor: MountTrustAnchor) {
  const expectedKeys = [
    "createdAtMs",
    "deviceId",
    "mountId",
    "shareId",
    "shareSessionKey",
    "targetKind",
    "targetTitle",
    "targetTokenHash",
    "userId",
    "workspacePinBootstrapHash",
  ];
  if (JSON.stringify(Object.keys(anchor).sort()) !== JSON.stringify(expectedKeys)) {
    throw new Error("mount_trust_anchor_invalid");
  }
  if (anchor.shareSessionKey !== mountedShareSessionKey(anchor.mountId)) {
    throw new Error("mount_trust_anchor_session_key_invalid");
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(anchor.workspacePinBootstrapHash)) {
    throw new Error("mount_trust_anchor_workspace_pin_bootstrap_hash_invalid");
  }

  return {
    authenticatedWorkspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
  };
}

export function mountedShareSessionKey(mountId: string): string {
  return `mount:${mountId}`;
}
