import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { recordShareSessionPerf } from "./perf";

const pendingShareParticipantKeypairPrewarms = new Map<string, Promise<void>>();

async function generateTransientShareParticipantKeypair(shareSlug: string): Promise<void> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const deviceId = crypto.randomUUID();
  await worker.lock();
  await worker.generateDeviceKeys({ deviceId, ownerKind: "share_participant_device" });
}

export function getPendingShareParticipantKeypairPrewarm(
  shareSlug: string,
): Promise<void> | undefined {
  return pendingShareParticipantKeypairPrewarms.get(shareSlug);
}

export function clearPendingShareParticipantKeypairPrewarm(
  shareSlug: string,
  pending: Promise<void>,
): void {
  if (pendingShareParticipantKeypairPrewarms.get(shareSlug) === pending) {
    pendingShareParticipantKeypairPrewarms.delete(shareSlug);
  }
}

export function prewarmShareParticipantKeypair(shareSlug: string): Promise<void> {
  const existing = pendingShareParticipantKeypairPrewarms.get(shareSlug);
  if (existing) {
    recordShareSessionPerf("share_session_keypair_prewarm_reused", { shareSlug });
    return existing;
  }

  const startedAt = performance.now();
  recordShareSessionPerf("share_session_keypair_prewarm_start", { shareSlug });
  const pending = generateTransientShareParticipantKeypair(shareSlug)
    .then(() => {
      recordShareSessionPerf("share_session_keypair_prewarm_ready", {
        shareSlug,
        elapsedMs: performance.now() - startedAt,
      });
    })
    .catch((error: unknown) => {
      clearPendingShareParticipantKeypairPrewarm(shareSlug, pending);
      recordShareSessionPerf("share_session_keypair_prewarm_failed", {
        shareSlug,
        elapsedMs: performance.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    });
  pending.then(
    () => {
      setTimeout(() => {
        if (pendingShareParticipantKeypairPrewarms.get(shareSlug) === pending) {
          pendingShareParticipantKeypairPrewarms.delete(shareSlug);
          recordShareSessionPerf("share_session_keypair_prewarm_expired", { shareSlug });
        }
      }, 30_000);
    },
    () => {},
  );
  pendingShareParticipantKeypairPrewarms.set(shareSlug, pending);
  return pending;
}
