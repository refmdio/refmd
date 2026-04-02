import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import {
  getDocumentStatePin,
  putDocumentStatePin,
  updatePinFromState,
  type DocumentStatePin,
} from "./document-state-pins";
import { collectClockObservations } from "./clock-observations";
export interface DocumentPayloadForValidation {
  snapshot?: {
    ciphertext: string;
    publicData: {
      snapshotId: string;
      parentSnapshotProof: string;
      parentSnapshotUpdateClocks: Record<string, number>;
    };
  };
  snapshotProofChain?: Array<{
    snapshotId: string;
    ciphertextHash: string;
    parentSnapshotProof: string;
  }>;
  updates: Array<{
    version: number;
    publicData: {
      signingPubKey: string;
      clock: number;
    };
  }>;
  latestVersion?: number;
}
interface ValidationResult {
  rollbackWarnings: string[];
  newPin: DocumentStatePin;
  snapshotProofHash: string;
  snapshotCiphertextHash: string;
}
export async function validateDocumentPayloadAgainstPin(
  documentId: string,
  payload: DocumentPayloadForValidation,
): Promise<ValidationResult> {
  const worker = getCryptoWorker();
  const pin = await getDocumentStatePin(documentId).catch(() => null);
  const rollbackWarnings: string[] = [];
  // Version rollback check
  let incomingVersion = payload.latestVersion ?? 0;
  if (payload.updates) {
    for (const u of payload.updates) {
      if (u.version > incomingVersion) incomingVersion = u.version;
    }
  }
  if (pin && incomingVersion > 0 && incomingVersion < pin.latestGlobalVersion) {
    rollbackWarnings.push(
      `Version rollback: server=${incomingVersion} < pin=${pin.latestGlobalVersion}`,
    );
  }
  // Clock rollback check
  if (pin) {
    const sameSnapshot = payload.snapshot
      ? payload.snapshot.publicData.snapshotId === pin.latestSnapshotId
      : true;
    if (sameSnapshot && payload.updates) {
      const clockObservations = collectClockObservations(payload.updates);
      for (const [deviceKey, pinnedClock] of Object.entries(pin.perDeviceMaxClocks)) {
        const observed = clockObservations.get(deviceKey);
        if (!observed) continue;
        if (observed.max < pinnedClock) {
          rollbackWarnings.push(
            `Clock rollback: device=${deviceKey} clock=${observed.max} < pin=${pinnedClock}`,
          );
        } else if (observed.max > pinnedClock + 1 && !observed.seen.has(pinnedClock + 1)) {
          rollbackWarnings.push(
            `Clock gap: device=${deviceKey} expected=${pinnedClock + 1} got=${observed.max}`,
          );
        }
      }
    }
  }
  // Proof chain verification
  const anchorSnapshotId = pin?.latestSnapshotId ?? null;
  const anchorProofHash = pin?.latestSnapshotProofHash ?? "";
  let snapshotProofHash = anchorProofHash;
  let snapshotCiphertextHash = pin?.latestSnapshotCiphertextHash ?? "";
  if (payload.snapshot && anchorSnapshotId) {
    const snapshotChanged = payload.snapshot.publicData.snapshotId !== anchorSnapshotId;
    if (snapshotChanged) {
      const chain = payload.snapshotProofChain ?? [];
      if (chain.length === 0) {
        throw new Error("Snapshot changed but no proof chain provided (rollback attack)");
      }
      // Verify chain head matches anchor
      if (chain[0].parentSnapshotProof !== anchorProofHash) {
        throw new Error("Proof chain head does not match pinned proof hash");
      }
      // Verify each intermediate link and chain terminus
      for (let i = 0; i < chain.length; i++) {
        const chainEntry = chain[i];
        const computedProof = await worker.computeSnapshotProof({
          ciphertextHash: chainEntry.ciphertextHash,
          parentProof: chainEntry.parentSnapshotProof,
          snapshotId: chainEntry.snapshotId,
        });
        if (i < chain.length - 1) {
          if (computedProof !== chain[i + 1].parentSnapshotProof) {
            throw new Error(`Proof chain link ${i} verification failed`);
          }
        }
      }
      // Chain tail must be the active snapshot
      const lastChainEntry = chain[chain.length - 1];
      if (lastChainEntry.snapshotId !== payload.snapshot!.publicData.snapshotId) {
        throw new Error("Proof chain does not terminate at active snapshot");
      }
      // Verify chain tail's ciphertextHash matches the actual snapshot content
      const actualHash = base64UrlEncode(
        await worker.blake3Hash(base64UrlDecode(payload.snapshot!.ciphertext)),
      );
      if (lastChainEntry.ciphertextHash !== actualHash) {
        throw new Error("Proof chain tail ciphertextHash does not match actual snapshot");
      }
    }
  }
  // Compute new proof hash for active snapshot
  if (payload.snapshot) {
    const ciphertextHash = base64UrlEncode(
      await worker.blake3Hash(base64UrlDecode(payload.snapshot.ciphertext)),
    );
    snapshotCiphertextHash = ciphertextHash;
    snapshotProofHash = await worker.computeSnapshotProof({
      ciphertextHash,
      parentProof: payload.snapshot.publicData.parentSnapshotProof,
      snapshotId: payload.snapshot.publicData.snapshotId,
    });
  }
  // Build confirmed clocks
  const confirmedClocks: Record<string, number> = {};
  if (payload.updates) {
    for (const update of payload.updates) {
      const key = update.publicData.signingPubKey;
      const clock = update.publicData.clock;
      if (clock > (confirmedClocks[key] ?? -1)) {
        confirmedClocks[key] = clock;
      }
    }
  }
  // Create updated pin
  const snapshotId = payload.snapshot?.publicData?.snapshotId ?? anchorSnapshotId;
  const newPin = updatePinFromState(
    pin,
    documentId,
    snapshotId,
    snapshotProofHash,
    snapshotCiphertextHash,
    confirmedClocks,
    incomingVersion,
  );
  return { rollbackWarnings, newPin, snapshotProofHash, snapshotCiphertextHash };
}
export async function persistPin(pin: DocumentStatePin): Promise<void> {
  await putDocumentStatePin(pin).catch(() => {});
}
