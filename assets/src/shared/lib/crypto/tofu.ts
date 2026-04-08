import { type TofuEntry, getTofuEntry, saveTofuEntry, updateLastSeen } from "./trust-store";
import { calculateFingerprint, formatFingerprint } from "./fingerprint";
import { constantTimeEqual, base64UrlDecode } from "./encoding";
import { verifyDeviceIdentitySignature } from "./device";
import { isValidEd25519PublicKey, isValidX25519PublicKey } from "./key-validation";
import type { DeviceInfo } from "@/shared/api/devices";
type TofuStatus = "first_seen" | "known_trusted" | "identity_key_changed" | "ecdh_key_mismatch";
interface TofuVerifyResult {
  status: TofuStatus;
  storedEntry?: TofuEntry;
  newEntry: TofuEntry;
  oldFingerprint?: string;
  newFingerprint?: string;
}
export async function verifyTofu(
  userId: string,
  deviceId: string,
  signingPublicKey: Uint8Array,
  ecdhPublicKey: Uint8Array,
): Promise<TofuVerifyResult> {
  if (!isValidEd25519PublicKey(signingPublicKey)) {
    throw new Error("Invalid Ed25519 signing public key");
  }
  if (!isValidX25519PublicKey(ecdhPublicKey)) {
    throw new Error("Invalid X25519 ECDH public key");
  }
  const now = Date.now();
  const newEntry: TofuEntry = {
    userId,
    deviceId,
    signingPublicKey,
    ecdhPublicKey,
    firstSeenAt: now,
    lastSeenAt: now,
  };
  const storedEntry = await getTofuEntry(userId, deviceId);
  if (!storedEntry) {
    return { status: "first_seen", newEntry };
  }
  const signingKeyMatches = constantTimeEqual(storedEntry.signingPublicKey, signingPublicKey);
  const ecdhKeyMatches = constantTimeEqual(storedEntry.ecdhPublicKey, ecdhPublicKey);
  if (signingKeyMatches && ecdhKeyMatches) {
    return {
      status: "known_trusted",
      storedEntry,
      newEntry: { ...newEntry, firstSeenAt: storedEntry.firstSeenAt },
    };
  }
  if (!signingKeyMatches) {
    const oldFp = formatFingerprint(calculateFingerprint(storedEntry.signingPublicKey));
    const newFp = formatFingerprint(calculateFingerprint(signingPublicKey));
    return {
      status: "identity_key_changed",
      storedEntry,
      newEntry,
      oldFingerprint: oldFp,
      newFingerprint: newFp,
    };
  }
  return { status: "ecdh_key_mismatch", storedEntry, newEntry };
}
export async function trustDevice(entry: TofuEntry): Promise<void> {
  await saveTofuEntry(entry);
}
export async function updateDeviceLastSeen(userId: string, deviceId: string): Promise<void> {
  await updateLastSeen(userId, deviceId);
}
export async function handleTofuResult(result: TofuVerifyResult): Promise<TofuVerifyResult> {
  switch (result.status) {
    case "first_seen":
      await trustDevice(result.newEntry);
      break;
    case "known_trusted":
      await updateDeviceLastSeen(result.newEntry.userId, result.newEntry.deviceId);
      break;
    case "identity_key_changed":
    case "ecdh_key_mismatch":
      break;
  }
  return result;
}
class TofuHardFailError extends Error {
  deviceName: string;
  status: "identity_key_changed" | "ecdh_key_mismatch";
  constructor(deviceName: string, status: "identity_key_changed" | "ecdh_key_mismatch") {
    const msg =
      status === "identity_key_changed"
        ? `${deviceName}: Identity key changed`
        : `${deviceName}: ECDH key mismatch`;
    super(msg);
    this.name = "TofuHardFailError";
    this.deviceName = deviceName;
    this.status = status;
  }
}
export async function verifyAllDeviceTofu(
  userId: string,
  devices: DeviceInfo[],
  identitySigningPublic: Uint8Array | null,
): Promise<string[]> {
  const warnings: string[] = [];
  for (const d of devices) {
    if (!d.signing_public_key || !d.ecdh_public_key) continue;
    try {
      const signingPk = base64UrlDecode(d.signing_public_key);
      const ecdhPk = base64UrlDecode(d.ecdh_public_key);
      const result = await verifyTofu(userId, d.id, signingPk, ecdhPk);
      if (result.status === "identity_key_changed" || result.status === "ecdh_key_mismatch") {
        throw new TofuHardFailError(d.name, result.status);
      }
      if (!d.identity_signature || !d.client_nonce) {
        warnings.push(`${d.name}: Missing identity signature`);
        continue;
      }
      if (!identitySigningPublic) {
        await handleTofuResult(result);
        continue;
      }
      const sig = base64UrlDecode(d.identity_signature);
      const nonce = base64UrlDecode(d.client_nonce);
      const sigValid = verifyDeviceIdentitySignature(
        signingPk,
        ecdhPk,
        nonce,
        sig,
        identitySigningPublic,
      );
      if (!sigValid) {
        warnings.push(`${d.name}: Invalid identity signature`);
        continue;
      }
      await handleTofuResult(result);
    } catch (e) {
      if (e instanceof TofuHardFailError) throw e;
      warnings.push(`${d.name}: Key verification unavailable`);
    }
  }
  return warnings;
}
