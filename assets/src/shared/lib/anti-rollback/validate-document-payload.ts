import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { computeSnapshotProofLinkHash } from "./snapshot-proof";
import {
  getDocumentStatePin,
  hasCompleteSnapshotPin,
  putDocumentStatePin,
  updatePinFromState,
  type DocumentStatePin,
} from "./document-state-pins";
import { collectClockObservations } from "./clock-observations";
import { documentClockKey } from "./clock-observations";
export interface DocumentPayloadForValidation {
  snapshot?: {
    ciphertext: string;
    publicData: {
      snapshotId: string;
      parentProofHash: string;
      parentSnapshotUpdateClocks: Record<string, number>;
    };
  };
  snapshotProofChain?: Array<{
    document_id: string;
    snapshot_id: string;
    parent_snapshot_id: string;
    parent_proof_hash: string;
    ciphertext_hash: string;
    snapshot_signature_hash: string;
    snapshot_admission_event_hash: string;
    proof_chain_hash: string;
  }>;
  updates: Array<{
    version: number;
    publicData: {
      signingKeyId: string;
      authorityContextKey?: string;
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

function collectClockContiguityWarnings(
  updates: DocumentPayloadForValidation["updates"],
  baselineClocks: Record<string, number>,
): string[] {
  const warnings: string[] = [];
  const observations = collectClockObservations(updates);

  for (const [deviceKey, observed] of observations) {
    const baselineClock = baselineClocks[deviceKey] ?? -1;
    if (observed.max < baselineClock) {
      warnings.push(
        `Clock rollback: device=${deviceKey} clock=${observed.max} < pin=${baselineClock}`,
      );
      continue;
    }

    let expected = baselineClock + 1;
    for (const clock of [...observed.seen].sort((a, b) => a - b)) {
      if (clock <= baselineClock) continue;
      if (clock > expected) {
        warnings.push(`Clock gap: device=${deviceKey} expected=${expected} got=${clock}`);
        break;
      }
      expected = clock + 1;
    }
  }

  return warnings;
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
      rollbackWarnings.push(
        ...collectClockContiguityWarnings(payload.updates, pin.perDeviceMaxClocks),
      );
    } else if (!sameSnapshot && payload.updates) {
      rollbackWarnings.push(
        ...collectClockContiguityWarnings(
          payload.updates,
          payload.snapshot?.publicData.parentSnapshotUpdateClocks ?? {},
        ),
      );
    }
  } else if (payload.updates) {
    rollbackWarnings.push(
      ...collectClockContiguityWarnings(
        payload.updates,
        payload.snapshot?.publicData.parentSnapshotUpdateClocks ?? {},
      ),
    );
  }
  // Proof chain verification
  const anchorSnapshotId = hasCompleteSnapshotPin(pin) ? pin.latestSnapshotId : null;
  const anchorProofHash = hasCompleteSnapshotPin(pin) ? pin.latestSnapshotProofHash : "";
  let snapshotProofHash = anchorProofHash;
  let snapshotCiphertextHash = hasCompleteSnapshotPin(pin) ? pin.latestSnapshotCiphertextHash : "";
  if (payload.snapshot && anchorSnapshotId) {
    const snapshotChanged = payload.snapshot.publicData.snapshotId !== anchorSnapshotId;
    if (snapshotChanged) {
      const chain = payload.snapshotProofChain ?? [];
      if (chain.length === 0) {
        throw new Error("Snapshot changed but no proof chain provided (rollback attack)");
      }
      // Verify chain head matches anchor
      if (chain[0].parent_proof_hash !== anchorProofHash) {
        throw new Error("Proof chain head does not match pinned proof hash");
      }
      // Verify each intermediate link and chain terminus
      for (let i = 0; i < chain.length; i++) {
        const chainEntry = chain[i];
        const computedProof = computeSnapshotProofLinkHash({
          documentId: chainEntry.document_id,
          snapshotId: chainEntry.snapshot_id,
          parentSnapshotId: chainEntry.parent_snapshot_id,
          parentProofHash: chainEntry.parent_proof_hash,
          ciphertextHash: chainEntry.ciphertext_hash,
          snapshotSignatureHash: chainEntry.snapshot_signature_hash,
          snapshotAdmissionEventHash: chainEntry.snapshot_admission_event_hash,
        });
        if (computedProof !== chainEntry.proof_chain_hash) {
          throw new Error(`Proof chain link ${i} proof hash verification failed`);
        }
        if (i < chain.length - 1) {
          if (computedProof !== chain[i + 1].parent_proof_hash) {
            throw new Error(`Proof chain link ${i} verification failed`);
          }
        }
      }
      // Chain tail must be the active snapshot
      const lastChainEntry = chain[chain.length - 1];
      if (lastChainEntry.snapshot_id !== payload.snapshot!.publicData.snapshotId) {
        throw new Error("Proof chain does not terminate at active snapshot");
      }
      if (lastChainEntry.parent_proof_hash !== payload.snapshot!.publicData.parentProofHash) {
        throw new Error("Proof chain tail parent proof does not match active snapshot");
      }
      // Verify chain tail's ciphertextHash matches the actual snapshot content
      const actualHash = base64UrlEncode(
        await worker.blake3Hash(base64UrlDecode(payload.snapshot!.ciphertext)),
      );
      if (lastChainEntry.ciphertext_hash !== actualHash) {
        throw new Error("Proof chain tail ciphertextHash does not match actual snapshot");
      }
      snapshotProofHash = lastChainEntry.proof_chain_hash;
    }
  }
  // Compute new proof hash for active snapshot
  if (payload.snapshot) {
    const ciphertextHash = base64UrlEncode(
      await worker.blake3Hash(base64UrlDecode(payload.snapshot.ciphertext)),
    );
    snapshotCiphertextHash = ciphertextHash;
  }
  // Build confirmed clocks
  const observedUpdateClocks: Record<string, number> = {};
  if (payload.updates) {
    for (const update of payload.updates) {
      const key = documentClockKey(update.publicData);
      const clock = update.publicData.clock;
      if (clock > (observedUpdateClocks[key] ?? -1)) {
        observedUpdateClocks[key] = clock;
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
    observedUpdateClocks,
    incomingVersion,
  );
  return { rollbackWarnings, newPin, snapshotProofHash, snapshotCiphertextHash };
}
export async function persistPin(pin: DocumentStatePin): Promise<void> {
  const existing = await getDocumentStatePin(pin.documentId).catch(() => null);
  await putDocumentStatePin(pin, {
    expectedPreviousSnapshotId: existing?.latestSnapshotId ?? null,
    allowSnapshotChangeAtSameVersion: true,
  }).catch(() => {});
}
