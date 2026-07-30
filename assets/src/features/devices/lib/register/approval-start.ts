import { devicesApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import type { components } from "@/shared/api/schema";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import { joinPendingRegistrationSecurityNotifications } from "@/shared/lib/security/notification-channel";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";
import type { DeviceRegistrationPublicKeys } from "../../model/register/types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { prepareRegistrationInitialAkeResponderPrekeys } from "@/shared/lib/auth/registration-initial-ake-prekeys";

interface StartRegistrationApprovalParams {
  userId: string;
  publicKeys: DeviceRegistrationPublicKeys;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  signal?: AbortSignal;
  shouldKeepWaiting: () => boolean;
  onReauthRequired: () => void;
  onApproved: (deviceId: string) => Promise<void>;
  onExpired: () => void;
  onRejected: () => void;
}

type StartRegistrationApprovalResult =
  | { status: "reauth_required"; clientNonce: Uint8Array }
  | { status: "waiting"; clientNonce: Uint8Array; dispose: () => void };
type RegistrationRequestWithAke = Extract<
  components["schemas"]["CreateDeviceRegistrationRequest"],
  { ake_responder_prekeys: unknown }
>;

export async function startRegistrationApproval(
  params: StartRegistrationApprovalParams,
): Promise<StartRegistrationApprovalResult> {
  const worker = getCryptoWorker();
  const clientNonce = await worker.generateClientNonce();

  try {
    const challenge = await devicesApi.registrationChallenge({ signal: params.signal });
    if (params.signal?.aborted) throw createAbortError();
    const initialAkeResponderPrekeys = await prepareRegistrationInitialAkeResponderPrekeys({
      userId: params.userId,
      deviceId: params.publicKeys.deviceId,
      serverChallenge: challenge.registration_challenge,
      issuedAtMs: challenge.issued_at_ms,
      expiresAtMs: challenge.expires_at_ms,
    });
    if (params.signal?.aborted) throw createAbortError();
    const registration = await devicesApi.createRegistration(
      {
        name: getDeviceName(),
        device_type: getDeviceType(),
        device_id: params.publicKeys.deviceId,
        identity_signing_key_id: computeSigningKeyId(params.identityHybridSigningPublicKeyMaterial),
        device_hybrid_encryption_public_key_material:
          params.publicKeys.hybridEncryptionPublicKeyMaterial,
        device_encryption_key_id: params.publicKeys.encryptionKeyId,
        device_hybrid_signing_public_key_material: params.publicKeys.hybridSigningPublicKeyMaterial,
        device_signing_key_id: params.publicKeys.signingKeyId,
        client_nonce: base64UrlEncode(clientNonce),
        registration_challenge: challenge.registration_challenge,
        ake_responder_prekeys:
          initialAkeResponderPrekeys as unknown as RegistrationRequestWithAke["ake_responder_prekeys"],
      },
      { signal: params.signal },
    );
    if (params.signal?.aborted) throw createAbortError();
    if (registration.status !== "pending") {
      throw new Error("device_registration_not_pending");
    }
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
  let securityNotifications: { dispose: () => void } | undefined;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let settled = false;
  let connectionGeneration = 0;

  const clearPolling = () => {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
  };

  const clearSecurityNotifications = () => {
    connectionGeneration += 1;
    const activeEvents = securityNotifications;
    securityNotifications = undefined;
    activeEvents?.dispose();
  };

  const dispose = () => {
    clearPolling();
    clearSecurityNotifications();
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = undefined;
    }
  };

  const approve = async () => {
    if (settled) return;
    settled = true;
    dispose();
    await params.onApproved(params.publicKeys.deviceId);
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

  const startStatusPolling = () => {
    if (pollTimer || settled) return;

    pollTimer = setInterval(async () => {
      try {
        const status = await devicesApi.getRegistrationSas(params.publicKeys.deviceId);
        if (status.status === "initial_ake_offers_ready" || status.status === "approved") {
          await approve();
        } else if (status.status === "expired") {
          expire();
        }
      } catch {
        // Polling error. Keep trying.
      }
    }, 5000);
  };

  const scheduleEventReconnect = (generation: number) => {
    if (generation !== connectionGeneration || reconnectTimer) return;

    const delay = Math.max(5000, getAuthTransportBackoffMs());
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined;
      if (!settled && params.shouldKeepWaiting() && generation === connectionGeneration) {
        connectSecurityNotifications();
      }
    }, delay);
  };

  const handleEventConnectionLoss = (generation: number) => {
    if (settled || generation !== connectionGeneration) return;

    clearSecurityNotifications();
    startStatusPolling();
    scheduleEventReconnect(connectionGeneration);
  };

  const connectSecurityNotifications = () => {
    if (settled) return;
    const generation = connectionGeneration;

    joinPendingRegistrationSecurityNotifications(params.publicKeys.deviceId, {
      onInitialAkeOffersReady: () => {
        void approve();
      },
      onApproved: () => {
        void approve();
      },
      onExpired: () => {
        expire();
      },
      onRejected: () => {
        reject();
      },
      onClose: () => {
        handleEventConnectionLoss(generation);
      },
      onError: () => handleEventConnectionLoss(generation),
    })
      .then((handle) => {
        if (generation !== connectionGeneration) {
          handle.dispose();
          return;
        }
        securityNotifications = handle;
      })
      .catch(() => {
        scheduleEventReconnect(generation);
      });
  };

  startStatusPolling();
  connectSecurityNotifications();

  return {
    status: "waiting",
    clientNonce,
    dispose,
  };
}

function createAbortError(): Error {
  const error = new Error("device_registration_cancelled");
  error.name = "AbortError";
  return error;
}
