import { devicesApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getDeviceName, getDeviceType } from "@/shared/lib/device-metadata";
import { requestTrustTransferNonce } from "./approval-support";
import type { DeviceRegistrationPublicKeys } from "../model/types";

interface StartRegistrationApprovalParams {
  publicKeys: DeviceRegistrationPublicKeys;
  identitySigningPublic: Uint8Array;
  shouldKeepWaiting: () => boolean;
  onReauthRequired: () => void;
  onApproved: (deviceId: string) => Promise<void>;
  onExpired: () => void;
  onRejected: () => void;
}

type StartRegistrationApprovalResult =
  | { status: "reauth_required"; clientNonce: Uint8Array }
  | { status: "waiting"; clientNonce: Uint8Array; dispose: () => void };

export async function startRegistrationApproval(
  params: StartRegistrationApprovalParams,
): Promise<StartRegistrationApprovalResult> {
  const worker = getCryptoWorker();
  const clientNonce = await worker.generateClientNonce();

  let registration;
  try {
    registration = await devicesApi.createRegistration({
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_ecdh_public_key: base64UrlEncode(params.publicKeys.ecdhPublic),
      device_signing_public_key: base64UrlEncode(params.publicKeys.signingPublic),
      client_nonce: base64UrlEncode(clientNonce),
      identity_signing_public_key: base64UrlEncode(params.identitySigningPublic),
    });
  } catch (registrationError) {
    if (
      registrationError instanceof ApiError &&
      registrationError.status === 403 &&
      registrationError.body?.error === "reauth_required"
    ) {
      params.onReauthRequired();
      return { status: "reauth_required", clientNonce };
    }
    throw registrationError;
  }

  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let eventSource: EventSource | undefined;
  let nonceRefreshTimer: ReturnType<typeof setInterval> | undefined;
  let settled = false;

  const clearPolling = () => {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
  };

  const clearEventSource = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = undefined;
    }
  };

  const dispose = () => {
    clearPolling();
    clearEventSource();
    if (nonceRefreshTimer) {
      clearInterval(nonceRefreshTimer);
      nonceRefreshTimer = undefined;
    }
  };

  const approve = async () => {
    if (settled) return;
    settled = true;
    dispose();
    await params.onApproved(registration.device_id);
  };

  const expire = () => {
    if (settled) return;
    settled = true;
    dispose();
    params.onExpired();
  };

  const reject = () => {
    if (settled) return;
    settled = true;
    dispose();
    params.onRejected();
  };

  void requestTrustTransferNonce(registration.device_id);
  nonceRefreshTimer = setInterval(
    () => {
      if (params.shouldKeepWaiting()) {
        void requestTrustTransferNonce(registration.device_id);
      }
    },
    4 * 60 * 1000,
  );

  const startPollingFallback = () => {
    if (pollTimer || settled) return;

    pollTimer = setInterval(async () => {
      try {
        const status = await devicesApi.getRegistrationSas(registration.device_id);
        if (status.status === "approved") {
          await approve();
        } else if (status.status === "expired") {
          expire();
        }
      } catch {
        // Polling error. Keep trying.
      }
    }, 5000);
  };

  const connectSse = () => {
    if (settled) return;

    try {
      eventSource = new EventSource(`/api/devices/registrations/${registration.device_id}/events`);

      eventSource.addEventListener("pending_approved", () => {
        void approve();
      });
      eventSource.addEventListener("expired", () => {
        expire();
      });
      eventSource.addEventListener("pending_rejected", () => {
        reject();
      });
      eventSource.onopen = () => {
        clearPolling();
      };
      eventSource.onerror = () => {
        clearEventSource();
        startPollingFallback();
        setTimeout(() => {
          if (!settled && params.shouldKeepWaiting() && !eventSource) {
            connectSse();
          }
        }, 5000);
      };
    } catch {
      startPollingFallback();
    }
  };

  connectSse();

  return {
    status: "waiting",
    clientNonce,
    dispose,
  };
}
