import {
  type TofuEntry,
  getTofuEntry,
  saveTofuEntry,
  updateLastSeen,
} from "../trust-store";
import { calculateFingerprint, formatFingerprint } from "./fingerprint";
import { constantTimeEqual } from "./encoding";

export type TofuStatus =
  | "first_seen"
  | "known_trusted"
  | "identity_key_changed"
  | "ecdh_key_mismatch";

export interface TofuVerifyResult {
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
  if (signingPublicKey.length !== 32) {
    throw new Error("Signing public key must be 32 bytes");
  }
  if (ecdhPublicKey.length !== 32) {
    throw new Error("ECDH public key must be 32 bytes");
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

  const signingKeyMatches = constantTimeEqual(
    storedEntry.signingPublicKey,
    signingPublicKey,
  );
  const ecdhKeyMatches = constantTimeEqual(
    storedEntry.ecdhPublicKey,
    ecdhPublicKey,
  );

  if (signingKeyMatches && ecdhKeyMatches) {
    return {
      status: "known_trusted",
      storedEntry,
      newEntry: { ...newEntry, firstSeenAt: storedEntry.firstSeenAt },
    };
  }

  if (!signingKeyMatches) {
    const oldFp = formatFingerprint(
      calculateFingerprint(storedEntry.signingPublicKey),
    );
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

export async function updateDeviceLastSeen(
  userId: string,
  deviceId: string,
): Promise<void> {
  await updateLastSeen(userId, deviceId);
}

export async function handleTofuResult(
  result: TofuVerifyResult,
): Promise<TofuVerifyResult> {
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
