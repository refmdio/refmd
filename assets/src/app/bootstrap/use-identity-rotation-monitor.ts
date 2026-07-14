import { createEffect, onCleanup } from "solid-js";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { rotateCurrentUserIdentity } from "@/features/devices";
import { encryptionApi } from "@/shared/api";
import { clientError } from "@/shared/lib/logger";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { lookupVerifiedKeyDirectoryCheckpointBodies } from "@/shared/lib/anti-rollback/key-directory-pin/pins";

const RETRY_DELAY_MS = 60_000;
const MAX_SCHEDULE_DELAY_MS = 60 * 60 * 1_000;

declare global {
  interface Window {
    __refmdE2EDisableIdentityRotationMonitor?: boolean;
  }
}

export function useIdentityRotationMonitor(): void {
  if (typeof window !== "undefined" && window.__refmdE2EDisableIdentityRotationMonitor) return;

  let timer: ReturnType<typeof setTimeout> | undefined;
  let running = false;

  const schedule = (delay: number) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void check(), delay);
  };

  const check = async () => {
    const auth = authState();
    const device = deviceState();
    if (running || !cryptoWorkerReady() || !auth || !device?.deviceId) {
      return;
    }

    running = true;
    try {
      const status = await encryptionApi.getIdentityRotationStatus({
        rrpDeviceId: device.deviceId,
      });
      const worker = getCryptoWorker();
      await worker.setIdentityRotationDeadline(status.rotation_due_at);
      const overdue =
        status.rotation_due_at !== null && Date.parse(status.rotation_due_at) <= Date.now();
      if (!overdue && status.pending_key_version === null) {
        const directory = await fetchVerifiedKeyDirectory({
          scopeKind: "user",
          scopeId: auth.user.id,
          rrpDeviceId: device.deviceId,
        });
        await worker.trustIdentityRotationCheckpoint({
          checkpointPayload: directory.checkpoint.payload as Record<string, unknown>,
          checkpointAncestryPayloads: lookupVerifiedKeyDirectoryCheckpointBodies(
            "user",
            auth.user.id,
          ).map((entry) => entry.payload),
        });
      }
      if (status.pending_key_version !== null || status.needs_rotation === true || overdue) {
        scheduleFromStatus(await rotateCurrentUserIdentity());
      } else {
        scheduleFromStatus(status);
      }
    } catch (error) {
      clientError("identity_rotation_failed", error);
      schedule(RETRY_DELAY_MS);
    } finally {
      running = false;
    }
  };

  const scheduleFromStatus = (status: { rotation_due_at: string | null }) => {
    const dueAt = status.rotation_due_at ? Date.parse(status.rotation_due_at) : Number.NaN;
    const delay = Number.isFinite(dueAt)
      ? Math.max(0, Math.min(dueAt - Date.now(), MAX_SCHEDULE_DELAY_MS))
      : MAX_SCHEDULE_DELAY_MS;
    schedule(delay);
  };

  createEffect(() => {
    const sessionId = authState()?.sessionId;
    const deviceId = deviceState()?.deviceId;
    const ready = cryptoWorkerReady();
    if (!sessionId || !deviceId || !ready) return;
    schedule(0);
  });

  onCleanup(() => {
    if (timer) clearTimeout(timer);
  });
}
