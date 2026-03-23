import { createSignal, onMount, onCleanup, Show, Match, Switch } from "solid-js";
import { useNavigate, useLocation, A } from "@solidjs/router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { ShieldCheckIcon, AlertTriangleIcon, CheckCircleIcon } from "lucide-solid";
import { SafetyNumber } from "@/features/devices";
import {
  authState,
  setFullSession,
  setDeviceState,
  setCryptoWorkerReady,
} from "@/shared/lib/auth-state";
import { authApi, devicesApi, encryptionApi, trustTransferApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import {
  persistDeviceId,
  persistWrappedDeviceKeys,
  persistWrappedUmk,
  persistSessionPdk,
} from "@/features/auth";
import { base64UrlEncode, base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

type Phase =
  | "generating"
  | "waiting"
  | "restoring"
  | "done"
  | "error"
  | "expired"
  | "needs_password"
  | "reauth";

export default function DeviceRegisterPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const isRecoveryFromState = () => (location.state as Record<string, unknown>)?.recovery === true;
  const [phase, setPhase] = createSignal<Phase>("generating");
  const [error, setError] = createSignal<string | null>(null);
  const [devicePublicKeys, setDevicePublicKeys] = createSignal<{
    ecdhPublic: Uint8Array;
    signingPublic: Uint8Array;
  } | null>(null);
  const [clientNonce, setClientNonce] = createSignal<Uint8Array | null>(null);
  const [identitySigningPublic, setIdentitySigningPublic] = createSignal<Uint8Array | null>(null);
  const [pendingKeysGenerated, setPendingKeysGenerated] = createSignal(false);
  const [postApprovalPersistence, setPostApprovalPersistence] = createSignal(false);
  const [dskUnavailableOAuth, setDskUnavailableOAuth] = createSignal(false);
  const [pdkPassword, setPdkPassword] = createSignal("");
  const [pdkLoading, setPdkLoading] = createSignal(false);
  const [pdkError, setPdkError] = createSignal<string | null>(null);
  const [statusMessage, setStatusMessage] = createSignal("");
  const [isRecoveryMode, setIsRecoveryMode] = createSignal(false);
  const [reauthPassword, setReauthPassword] = createSignal("");
  const [reauthLoading, setReauthLoading] = createSignal(false);
  const [reauthError, setReauthError] = createSignal<string | null>(null);
  const [reauthPendingPublicKeys, setReauthPendingPublicKeys] = createSignal<{
    ecdhPublic: Uint8Array;
    signingPublic: Uint8Array;
  } | null>(null);
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let eventSource: EventSource | undefined;
  let nonceRefreshTimer: ReturnType<typeof setInterval> | undefined;
  let redirectTimer: ReturnType<typeof setTimeout> | undefined;

  onCleanup(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (eventSource) eventSource.close();
    if (nonceRefreshTimer) clearInterval(nonceRefreshTimer);
    if (redirectTimer) clearTimeout(redirectTimer);
  });

  onMount(async () => {
    const auth = authState();
    if (!auth) {
      navigate("/auth/login");
      return;
    }

    try {
      // Check recovery mode from location state (initial navigation) or server session (page refresh)
      let isRecovery = isRecoveryFromState();
      if (!isRecovery) {
        const me = await authApi.me();
        isRecovery = me.is_recovery === true;
      }

      setIsRecoveryMode(isRecovery);

      if (isRecovery) {
        await startRecoveryRegistration(auth);
      } else {
        await startNormalRegistration(auth);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
      setPhase("error");
    }
  });

  // Normal flow: emoji approval from existing device
  const startNormalRegistration = async (auth: NonNullable<ReturnType<typeof authState>>) => {
    const me = await authApi.me();

    if (!me.identity_signing_public_key) {
      throw new Error("Identity key not available");
    }
    setIdentitySigningPublic(base64UrlDecode(me.identity_signing_public_key));

    const worker = getCryptoWorker();
    await worker.setUserContext(auth.user.id);

    // Ensure DSK exists and is loaded into Worker
    const { loadDsk } = await import("@/shared/lib/crypto/dsk");
    let hadDsk = false;
    let dsk = await loadDsk();
    if (dsk) {
      await worker.setDsk(dsk);
      dsk = null;
      hadDsk = true;
    } else {
      try {
        await worker.generateDsk();
        hadDsk = true;
      } catch {
        // DSK unavailable
      }
    }

    const publicKeys = await worker.generateDeviceKeys();
    setDevicePublicKeys(publicKeys);

    // Persist device keys (wrapped via DSK in worker)
    if (hadDsk) {
      try {
        const wrapped = await worker.wrapDeviceKeysWithDsk(auth.user.id);
        await persistWrappedDeviceKeys(wrapped);
      } catch {
        setPendingKeysGenerated(true);
        setPhase("needs_password");
        return;
      }
    } else {
      const me = await authApi.me();
      if (me.auth_type === "password") {
        setPendingKeysGenerated(true);
        setPhase("needs_password");
        return;
      }
      // OAuth + no DSK: keys live in Worker memory only for this session.
      // Show limitation warning but allow continuation.
      setDskUnavailableOAuth(true);
    }

    await createRegistrationAndWait(publicKeys);
  };

  // Create pending device and set up SSE/polling for approval
  const createRegistrationAndWait = async (publicKeys: {
    ecdhPublic: Uint8Array;
    signingPublic: Uint8Array;
  }) => {
    const worker = getCryptoWorker();
    const nonce = await worker.generateClientNonce();
    setClientNonce(nonce);

    let res;
    try {
      res = await devicesApi.createRegistration({
        name: getDeviceName(),
        device_type: getDeviceType(),
        device_ecdh_public_key: base64UrlEncode(publicKeys.ecdhPublic),
        device_signing_public_key: base64UrlEncode(publicKeys.signingPublic),
        client_nonce: base64UrlEncode(nonce),
        identity_signing_public_key: base64UrlEncode(identitySigningPublic()!),
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 403 && err.body?.error === "reauth_required") {
        setReauthPendingPublicKeys(publicKeys);
        setPhase("reauth");
        return;
      }
      throw err;
    }

    setPhase("waiting");

    // Request trust transfer nonce (best-effort, non-blocking)
    // Refresh every 4 minutes to stay within the 5-minute server TTL
    requestTrustTransferNonce(res.device_id);
    nonceRefreshTimer = setInterval(
      () => {
        if (phase() === "waiting") {
          requestTrustTransferNonce(res.device_id);
        }
      },
      4 * 60 * 1000,
    );

    const startPollingFallback = () => {
      if (pollTimer) return;
      pollTimer = setInterval(async () => {
        try {
          const status = await devicesApi.getRegistrationSas(res.device_id);
          if (status.status === "approved") {
            if (pollTimer) clearInterval(pollTimer);
            await handleApproved(res.device_id, publicKeys);
          } else if (status.status === "expired") {
            if (pollTimer) clearInterval(pollTimer);
            setPhase("expired");
          }
        } catch {
          // Polling error — continue
        }
      }, 5000);
    };

    const connectSse = () => {
      try {
        eventSource = new EventSource(`/api/devices/registrations/${res.device_id}/events`);
        eventSource.addEventListener("pending_approved", async () => {
          if (eventSource) eventSource.close();
          if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = undefined;
          }
          await handleApproved(res.device_id, publicKeys);
        });
        eventSource.addEventListener("expired", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = undefined;
          }
          setPhase("expired");
        });
        eventSource.addEventListener("pending_rejected", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = undefined;
          }
          setError("Device registration was rejected by an existing device.");
          setPhase("error");
        });
        eventSource.onopen = () => {
          if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = undefined;
          }
        };
        eventSource.onerror = () => {
          if (eventSource) {
            eventSource.close();
            eventSource = undefined;
          }
          startPollingFallback();
          setTimeout(() => {
            if (phase() === "waiting" && !eventSource) connectSse();
          }, 5000);
        };
      } catch {
        startPollingFallback();
      }
    };

    connectSse();
  };

  // Recovery flow: self-approve with identity signature
  const startRecoveryRegistration = async (auth: NonNullable<ReturnType<typeof authState>>) => {
    const worker = getCryptoWorker();

    // After page refresh, Worker has no keys. Redirect to recovery page.
    const pubKeys = await worker.getPublicKeys();
    if (!pubKeys.identitySigningPublic) {
      navigate("/auth/recovery");
      return;
    }

    setPhase("generating");
    setStatusMessage("Generating device keys\u2026");
    await worker.setUserContext(auth.user.id);

    // Ensure DSK exists and is loaded into Worker
    const { loadDsk: loadDskRec } = await import("@/shared/lib/crypto/dsk");
    let hadDskRec = false;
    let dskRec = await loadDskRec();
    if (dskRec) {
      await worker.setDsk(dskRec);
      dskRec = null;
      hadDskRec = true;
    } else {
      try {
        await worker.generateDsk();
        hadDskRec = true;
      } catch {
        // DSK unavailable
      }
    }

    const publicKeys = await worker.generateDeviceKeys();

    // Persist device keys (best-effort — recovery must not block on persistence)
    if (hadDskRec) {
      const wrapped = await worker.wrapDeviceKeysWithDsk(auth.user.id);
      await persistWrappedDeviceKeys(wrapped);
    }
    // No DSK: device keys live in Worker memory. PDK persistence deferred to password-set flow.

    setPhase("restoring");
    setStatusMessage("Registering device\u2026");

    const nonce = await worker.generateClientNonce();
    const { signature: deviceSignature } = await worker.signDeviceRegistration({
      deviceSigningPublic: publicKeys.signingPublic,
      deviceEcdhPublic: publicKeys.ecdhPublic,
      clientNonce: nonce,
    });

    const identitySigningPub = auth.identitySigningPublic;
    if (!identitySigningPub) throw new Error("Identity signing public key not available");

    const pendingRes = await devicesApi.createRegistration({
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_ecdh_public_key: base64UrlEncode(publicKeys.ecdhPublic),
      device_signing_public_key: base64UrlEncode(publicKeys.signingPublic),
      client_nonce: base64UrlEncode(nonce),
      identity_signing_public_key: base64UrlEncode(identitySigningPub),
    });

    const approveRes = await devicesApi.approve(pendingRes.device_id, {
      identity_signature: base64UrlEncode(deviceSignature),
    });

    const deviceId = approveRes.device.id;

    persistDeviceId(deviceId);

    // Set Worker context and mark initialized for PoP and subsequent operations
    await worker.setUserContext(auth.user.id, deviceId);
    await worker.setInitialized();
    setCryptoWorkerReady(true);

    // Persist UMK + device keys
    if (hadDskRec) {
      const wrappedUmk = await worker.wrapUmkWithDsk(auth.user.id);
      await persistWrappedUmk({
        wrappedUmk,
        kmsi: false,
        userId: auth.user.id,
      });
    }
    // DSK-unavailable: persistence deferred to password-set flow (/auth/recovery → password set)
    // Recovery proceeds without blocking — keys live in Worker memory until persisted

    setFullSession(
      {
        user: auth.user,
        sessionId: auth.sessionId,
        identitySigningPublic: auth.identitySigningPublic,
        identityEcdhPublic: auth.identityEcdhPublic,
        expiresAt: auth.expiresAt,
      },
      {
        deviceId,
        deviceSigningPublic: publicKeys.signingPublic,
        deviceEcdhPublic: publicKeys.ecdhPublic,
      },
    );

    setStatusMessage("Restoring workspace keys\u2026");
    const kekResults = await restoreWorkspaceKeks(auth.user.id, deviceId);

    if (kekResults.backupDecryptFailed) {
      setPhase("error");
      setError(
        "KEK backup decryption failed. This may indicate data corruption. Some workspaces may require key distribution from an existing device.",
      );
      return;
    }

    // PDK persistence for DSK-unavailable environments (password users only)
    if (!hadDskRec) {
      try {
        const meForPdk = await authApi.me();
        if (meForPdk.auth_type === "password") {
          setPostApprovalPersistence(true);
          setPhase("needs_password");
          return;
        }
      } catch {
        // Best effort
      }
    }

    await worker.clearTransientKeys();
    setPhase("done");
    if (kekResults.needsDistribution.length > 0) {
      setStatusMessage(
        `Recovery complete. ${kekResults.needsDistribution.length} workspace(s) require key distribution from an existing device.`,
      );
    } else {
      setStatusMessage("Recovery complete!");
    }
    const pendingInvite = sessionStorage.getItem("refmd_invite_token");
    redirectTimer = setTimeout(() => navigate(pendingInvite ? "/invite" : "/"), 3000);
  };

  const handlePdkReentry = async (e: Event) => {
    e.preventDefault();
    setPdkError(null);
    setPdkLoading(true);

    try {
      const auth = authState();
      if (!auth) throw new Error("No session");

      const saltRes = await authApi.getSalt(auth.user.email);
      const worker = getCryptoWorker();
      const { authKey } = await worker.deriveAuthKeys({
        password: pdkPassword(),
        salt: base64UrlDecode(saltRes.salt),
        kdfParams: saltRes.kdf_params,
      });
      await authApi.verifyKey(base64UrlEncode(authKey));
      persistSessionPdk(new Uint8Array(1));

      if (!pendingKeysGenerated()) throw new Error("No pending keys");

      // Try DSK first, fall back to PDK
      const { loadDsk: loadDskPdk } = await import("@/shared/lib/crypto/dsk");
      let dskPdk = await loadDskPdk();
      if (dskPdk) {
        await worker.setDsk(dskPdk);
        dskPdk = null;
        const wrapped = await worker.wrapDeviceKeysWithDsk(auth.user.id);
        await persistWrappedDeviceKeys(wrapped);
      } else {
        const pdkWrapped = await worker.wrapWithPdk({
          passwordParams: {
            password: pdkPassword(),
            salt: base64UrlDecode(saltRes.salt),
            kdfParams: saltRes.kdf_params,
          },
        });
        if (pdkWrapped.wrappedDeviceKeys) {
          localStorage.setItem(
            "refmd-pdk-device-ecdh",
            JSON.stringify(pdkWrapped.wrappedDeviceKeys.ecdh),
          );
          localStorage.setItem(
            "refmd-pdk-device-signing",
            JSON.stringify(pdkWrapped.wrappedDeviceKeys.signing),
          );
        }
        if (pdkWrapped.wrappedUmk) {
          localStorage.setItem("refmd-pdk-umk", JSON.stringify(pdkWrapped.wrappedUmk));
        }
      }

      await worker.clearTransientKeys();

      if (postApprovalPersistence()) {
        // Device already approved — persistence done, navigate to dashboard
        setPostApprovalPersistence(false);
        setPhase("done");
        const pendingInvite = sessionStorage.getItem("refmd_invite_token");
        navigate(pendingInvite ? "/invite" : "/dashboard");
        return;
      }

      const pubKeys = devicePublicKeys();
      if (!pubKeys) throw new Error("No device public keys");
      setPendingKeysGenerated(false);
      await createRegistrationAndWait(pubKeys);
    } catch (err) {
      setPdkError(err instanceof Error ? err.message : "Password verification failed");
      await getCryptoWorker()
        .clearTransientKeys()
        .catch(() => {});
    } finally {
      setPdkLoading(false);
    }
  };

  const handleReauth = async (e: Event) => {
    e.preventDefault();
    setReauthError(null);
    setReauthLoading(true);

    try {
      const auth = authState();
      if (!auth) throw new Error("No session");

      const saltRes = await authApi.getSalt(auth.user.email);
      const reauthWorker = getCryptoWorker();
      const { authKey: reauthKey } = await reauthWorker.deriveAuthKeys({
        password: reauthPassword(),
        salt: base64UrlDecode(saltRes.salt),
        kdfParams: saltRes.kdf_params,
      });
      await authApi.verifyKey(base64UrlEncode(reauthKey));
      await reauthWorker.clearTransientKeys();

      const pubKeys = reauthPendingPublicKeys();
      if (!pubKeys) throw new Error("No pending keys");
      setReauthPendingPublicKeys(null);
      await createRegistrationAndWait(pubKeys);
    } catch (err) {
      setReauthError(err instanceof Error ? err.message : "Password verification failed");
      await getCryptoWorker()
        .clearTransientKeys()
        .catch(() => {});
    } finally {
      setReauthLoading(false);
    }
  };

  const requestTrustTransferNonce = async (deviceId: string) => {
    try {
      const res = await trustTransferApi.requestNonce(deviceId);
      sessionStorage.setItem(`refmd-transfer-nonce-${deviceId}`, res.nonce);
    } catch {
      // Best-effort: if nonce request fails, trust state transfer won't happen
    }
  };

  const handleApproved = async (
    deviceId: string,
    publicKeys: {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    },
  ) => {
    setPhase("restoring");
    const auth = authState();
    if (!auth) return;

    try {
      const worker = getCryptoWorker();
      persistDeviceId(deviceId);
      await worker.setUserContext(auth.user.id, deviceId);

      // Trust state transfer retrieval (best-effort, BEFORE PoP binding)
      // Must happen before any PoP call because PoP auto-binds the session,
      // and trust-transfer endpoints reject bound sessions.
      try {
        await retrieveAndImportTrustState(auth.user.id, deviceId);
      } catch (err) {
        // identity_key_changed / ecdh_key_mismatch are hard failures
        if (err instanceof Error && err.message.includes("key verification failed")) {
          throw err;
        }
        // Other failures (404, network, decryption) are best-effort
      }

      setDeviceState({
        deviceId,
        deviceSigningPublic: publicKeys.signingPublic,
        deviceEcdhPublic: publicKeys.ecdhPublic,
      });

      // Get UMK from server (distributed by existing device, PoP required)
      const umkData = await retryGetUmk(deviceId, 10, 2000, deviceId);

      // TOFU verification on UMK sender
      if (!umkData.sender_signing_public_key || !umkData.sender_ecdh_public_key) {
        throw new Error("UMK response missing sender keys");
      }
      const senderSigningPk = base64UrlDecode(umkData.sender_signing_public_key);
      const senderEcdhPk = base64UrlDecode(umkData.sender_ecdh_public_key);
      const senderTofuResult = await worker.tofuVerify({
        userId: auth.user.id,
        deviceId: umkData.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });

      if (senderTofuResult.status === "identity_key_changed") {
        throw new Error("UMK sender identity key changed. This may indicate tampering.");
      }
      if (senderTofuResult.status === "ecdh_key_mismatch") {
        throw new Error("UMK sender ECDH key mismatch. This may indicate tampering.");
      }

      // Auto-trust sender for first_seen / update last_seen for known_trusted
      if (senderTofuResult.status === "first_seen") {
        await worker.tofuTrustDevice({
          userId: auth.user.id,
          deviceId: umkData.sender_device_id,
          signingPublicKey: senderSigningPk,
          ecdhPublicKey: senderEcdhPk,
        });
      } else if (senderTofuResult.status === "known_trusted") {
        await worker.tofuUpdateLastSeen({
          userId: auth.user.id,
          deviceId: umkData.sender_device_id,
        });
      }

      // Decrypt UMK via ECDH and store directly in Worker (UMK never leaves Worker)
      const senderEcdhPublic = base64UrlDecode(umkData.sender_ecdh_public_key!);
      await worker.ecdhDecryptUmkFromDevice({
        theirPublic: senderEcdhPublic,
        ciphertext: base64UrlDecode(umkData.encrypted_umk),
        nonce: base64UrlDecode(umkData.nonce),
        senderDeviceId: umkData.sender_device_id,
        targetDeviceId: deviceId,
      });

      // Import identity keys into worker (UMK-encrypted, Worker already has UMK)
      const me = await authApi.me();
      let identityPublicKeys: { signingPublic: Uint8Array; ecdhPublic: Uint8Array } | null = null;
      if (me.keys) {
        const pubKeys = await worker.importIdentityKeys({
          encryptedEcdhPrivate: base64UrlDecode(me.keys.encrypted_ecdh_private),
          ecdhPrivateNonce: base64UrlDecode(me.keys.encrypted_ecdh_private_nonce),
          encryptedSigningPrivate: base64UrlDecode(me.keys.encrypted_signing_private),
          signingPrivateNonce: base64UrlDecode(me.keys.encrypted_signing_private_nonce),
        });
        identityPublicKeys = {
          signingPublic: pubKeys.identitySigningPublic!,
          ecdhPublic: pubKeys.identityEcdhPublic!,
        };
      }

      // Device is now fully initialized with UMK + identity keys
      await worker.setInitialized();
      setCryptoWorkerReady(true);

      // Persist UMK
      const { loadDsk: loadDskForUmk } = await import("@/shared/lib/crypto/dsk");
      const umkDsk = await loadDskForUmk();
      if (umkDsk) {
        const wrappedUmk = await worker.wrapUmkWithDsk(auth.user.id);
        await persistWrappedUmk({
          wrappedUmk,
          kmsi: !!me.remember_me,
          userId: auth.user.id,
        });
      }
      // No DSK: keys live in Worker memory for this session.
      // PDK persistence is best-effort — do not block session finalization.

      setFullSession(
        {
          user: auth.user,
          sessionId: auth.sessionId,
          identitySigningPublic: identityPublicKeys?.signingPublic ?? null,
          identityEcdhPublic: identityPublicKeys?.ecdhPublic ?? null,
          expiresAt: auth.expiresAt,
        },
        {
          deviceId,
          deviceSigningPublic: publicKeys.signingPublic,
          deviceEcdhPublic: publicKeys.ecdhPublic,
        },
      );

      // Restore any workspace KEKs not distributed by the existing device (best-effort fallback)
      if (identityPublicKeys) {
        try {
          await restoreWorkspaceKeks(auth.user.id, deviceId);
        } catch {
          // KEK restoration is best-effort
        }
      }

      // PDK persistence for DSK-unavailable environments
      if (!umkDsk) {
        try {
          const meForPdk = await authApi.me();
          if (meForPdk.auth_type === "password") {
            setPostApprovalPersistence(true);
            setPhase("needs_password");
            return;
          }
          // OAuth + no DSK: keys only in Worker memory for this session
          setDskUnavailableOAuth(true);
        } catch {
          // Best effort
        }
      }

      await worker.clearTransientKeys();
      setPhase("done");
      const pendingInvite = sessionStorage.getItem("refmd_invite_token");
      navigate(pendingInvite ? "/invite" : "/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Key restoration failed");
      setPhase("error");
    }
  };

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-md">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <ShieldCheckIcon class="size-6" />
            New Device
          </CardTitle>
          <CardDescription>
            {isRecoveryMode() ? (
              "Setting up your recovered device\u2026"
            ) : (
              <>
                Verify this device from an existing device, or{" "}
                <A href="/auth/recovery" class="text-primary underline underline-offset-4">
                  use your recovery key
                </A>
                .
              </>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Show when={dskUnavailableOAuth()}>
            <Alert class="mb-4">
              <AlertTriangleIcon />
              <AlertDescription>
                Your browser does not support persistent key storage. Device keys will only be
                available for this session. After closing the browser, you will need to re-approve
                this device. Consider using password authentication for persistent access.
              </AlertDescription>
            </Alert>
          </Show>
          <Switch>
            <Match when={phase() === "generating"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <Spinner class="size-6" />
                <p class="text-sm text-muted-foreground">
                  {statusMessage() || "Generating device keys..."}
                </p>
              </div>
            </Match>

            <Match when={phase() === "waiting"}>
              <div class="space-y-6">
                <div class="space-y-2 text-center">
                  <p class="text-sm text-muted-foreground">
                    Verify that the same emojis appear on your existing device:
                  </p>
                </div>

                <Show when={identitySigningPublic() && devicePublicKeys() && clientNonce()}>
                  <SafetyNumber
                    identitySigningPublic={identitySigningPublic()!}
                    deviceSigningPublic={devicePublicKeys()!.signingPublic}
                    deviceEcdhPublic={devicePublicKeys()!.ecdhPublic}
                    clientNonce={clientNonce()!}
                    class="py-4"
                  />
                </Show>

                <div class="flex flex-col items-center gap-2">
                  <Spinner class="size-4" />
                  <p class="text-xs text-muted-foreground">
                    Waiting for approval from an existing device...
                  </p>
                </div>
              </div>
            </Match>

            <Match when={phase() === "restoring"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <Spinner class="size-6" />
                <p class="text-sm text-muted-foreground">
                  {statusMessage() || "Restoring encryption keys..."}
                </p>
              </div>
            </Match>

            <Match when={phase() === "done" && isRecoveryMode()}>
              <div class="flex flex-col items-center gap-4 py-8">
                <div class="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
                  <CheckCircleIcon class="size-6 text-green-600" />
                </div>
                <p class="text-lg font-medium">Recovery Successful!</p>
                <p class="text-sm text-muted-foreground">Redirecting to your workspace&hellip;</p>
              </div>
            </Match>

            <Match when={phase() === "needs_password"}>
              <form onSubmit={handlePdkReentry} class="space-y-4">
                <p class="text-sm text-muted-foreground">
                  Your browser storage was cleared. Please re-enter your password to continue.
                </p>
                <Show when={pdkError()}>
                  {(err) => (
                    <Alert variant="destructive">
                      <AlertTriangleIcon />
                      <AlertDescription>{err()}</AlertDescription>
                    </Alert>
                  )}
                </Show>
                <Field>
                  <FieldLabel for="pdk-password">Password</FieldLabel>
                  <Input
                    id="pdk-password"
                    type="password"
                    placeholder="--------"
                    value={pdkPassword()}
                    onInput={(e) => setPdkPassword(e.currentTarget.value)}
                    required
                    disabled={pdkLoading()}
                    autocomplete="current-password"
                  />
                </Field>
                <Button type="submit" class="w-full" disabled={pdkLoading()}>
                  {pdkLoading() ? (
                    <span class="flex items-center gap-2">
                      <Spinner class="size-3" /> Verifying...
                    </span>
                  ) : (
                    "Continue"
                  )}
                </Button>
              </form>
            </Match>

            <Match when={phase() === "reauth"}>
              <form onSubmit={handleReauth} class="space-y-4">
                <p class="text-sm text-muted-foreground">
                  Re-enter your password to authorize device registration.
                </p>
                <Show when={reauthError()}>
                  {(err) => (
                    <Alert variant="destructive">
                      <AlertTriangleIcon />
                      <AlertDescription>{err()}</AlertDescription>
                    </Alert>
                  )}
                </Show>
                <Field>
                  <FieldLabel for="reauth-password">Password</FieldLabel>
                  <Input
                    id="reauth-password"
                    type="password"
                    placeholder="--------"
                    value={reauthPassword()}
                    onInput={(e) => setReauthPassword(e.currentTarget.value)}
                    required
                    disabled={reauthLoading()}
                    autocomplete="current-password"
                  />
                </Field>
                <Button type="submit" class="w-full" disabled={reauthLoading()}>
                  {reauthLoading() ? (
                    <span class="flex items-center gap-2">
                      <Spinner class="size-3" /> Verifying...
                    </span>
                  ) : (
                    "Continue"
                  )}
                </Button>
              </form>
            </Match>

            <Match when={phase() === "expired"}>
              <div class="space-y-4">
                <Alert variant="destructive">
                  <AlertTriangleIcon />
                  <AlertDescription>
                    Device registration expired. Please try again.
                  </AlertDescription>
                </Alert>
                <Button class="w-full" onClick={() => window.location.reload()}>
                  Try Again
                </Button>
              </div>
            </Match>

            <Match when={phase() === "error"}>
              <div class="space-y-4">
                <Alert variant="destructive">
                  <AlertTriangleIcon />
                  <AlertDescription>{error()}</AlertDescription>
                </Alert>
                <Button class="w-full" onClick={() => navigate("/auth/login")}>
                  Back to Login
                </Button>
              </div>
            </Match>
          </Switch>
        </CardContent>
      </Card>
    </main>
  );
}

async function retryGetUmk(
  deviceId: string,
  maxAttempts: number,
  delayMs: number,
  popDeviceId?: string,
): Promise<Awaited<ReturnType<typeof devicesApi.getUmk>>> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      return await devicesApi.getUmk(deviceId, popDeviceId ? { popDeviceId } : undefined);
    } catch (err) {
      if (i === maxAttempts - 1) throw err;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error("UMK retrieval failed after retries");
}

async function retrieveAndImportTrustState(userId: string, deviceId: string): Promise<void> {
  let state;
  try {
    state = await trustTransferApi.retrieveState(deviceId);
  } catch {
    // No trust state available (404 or error) — start with empty TOFU store
    return;
  }

  if (!state.sender_ecdh_public_key || !state.sender_signing_public_key) return;

  const senderEcdhPublic = base64UrlDecode(state.sender_ecdh_public_key);
  const senderSigningPk = base64UrlDecode(state.sender_signing_public_key);

  const worker = getCryptoWorker();

  // TOFU check: reject if sender keys have changed (indicates tampering).
  // first_seen is accepted because trust transfer is protected by AEAD + signature verification.
  const senderTofuResult = await worker.tofuVerify({
    userId,
    deviceId: state.sender_device_id,
    signingPublicKey: senderSigningPk,
    ecdhPublicKey: senderEcdhPublic,
  });

  if (
    senderTofuResult.status === "identity_key_changed" ||
    senderTofuResult.status === "ecdh_key_mismatch"
  ) {
    throw new Error("Trust state sender key verification failed");
  }

  // Verify transfer nonce
  const storedNonce = sessionStorage.getItem(`refmd-transfer-nonce-${deviceId}`);
  if (!storedNonce) return;

  const expectedNonce = base64UrlDecode(storedNonce);

  // Decrypt, verify, and import trust state (Worker-internal: signature + AEAD + nonce + TOFU import)
  // decryptTrustState MUST complete before TOFU persistence to prevent store poisoning
  await worker.decryptTrustState({
    senderDeviceEcdhPublic: senderEcdhPublic,
    senderIdentitySigningPublic: senderSigningPk,
    senderDeviceId: state.sender_device_id,
    transferNonce: expectedNonce,
    ciphertext: base64UrlDecode(state.ciphertext),
    nonce: base64UrlDecode(state.nonce),
    signature: base64UrlDecode(state.signature),
  });

  // Persist sender TOFU only after cryptographic verification succeeded
  if (senderTofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId,
      deviceId: state.sender_device_id,
      signingPublicKey: senderSigningPk,
      ecdhPublicKey: senderEcdhPublic,
    });
  } else if (senderTofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({ userId, deviceId: state.sender_device_id });
  }

  sessionStorage.removeItem(`refmd-transfer-nonce-${deviceId}`);
}

interface KekRestoreResults {
  needsDistribution: string[];
  backupDecryptFailed: boolean;
}

class BackupDecryptError extends Error {
  constructor(workspaceId: string) {
    super(`KEK backup decryption failed for workspace ${workspaceId}`);
    this.name = "BackupDecryptError";
  }
}

async function restoreWorkspaceKeks(userId: string, deviceId: string): Promise<KekRestoreResults> {
  const result: KekRestoreResults = { needsDistribution: [], backupDecryptFailed: false };
  const { workspace_ids } = await encryptionApi.getWorkspaceIds();

  for (const workspaceId of workspace_ids) {
    try {
      const status = await restoreKekForWorkspace(workspaceId, userId, deviceId);
      if (status === "needs_distribution") {
        result.needsDistribution.push(workspaceId);
      }
    } catch (err) {
      if (err instanceof BackupDecryptError) {
        result.backupDecryptFailed = true;
      }
      // Other errors (network, etc.) are non-fatal per-workspace
    }
  }

  return result;
}

async function restoreKekForWorkspace(
  workspaceId: string,
  userId: string,
  deviceId: string,
): Promise<"restored" | "needs_distribution"> {
  const worker = getCryptoWorker();

  let currentKekVersion = 0;
  try {
    const existing = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId);
    if (existing.keys.some((k) => k.is_active)) return "restored";
    currentKekVersion = existing.current_kek_version;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      currentKekVersion =
        (e.body.details as { current_kek_version?: number })?.current_kek_version ?? 0;
    } else {
      throw e;
    }
  }

  const memberEnvelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (
    memberEnvelope &&
    memberEnvelope.sender_ecdh_public_key &&
    memberEnvelope.sender_signing_public_key
  ) {
    const senderEcdhPk = base64UrlDecode(memberEnvelope.sender_ecdh_public_key);
    const senderSigningPk = base64UrlDecode(memberEnvelope.sender_signing_public_key);

    const tofuResult = await worker.tofuVerify({
      userId: memberEnvelope.sender_user_id,
      deviceId: memberEnvelope.sender_device_id,
      signingPublicKey: senderSigningPk,
      ecdhPublicKey: senderEcdhPk,
    });
    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      throw new Error("Key verification failed for member envelope sender. Aborting KEK recovery.");
    }
    if (tofuResult.status === "first_seen") {
      await worker.tofuTrustDevice({
        userId: memberEnvelope.sender_user_id,
        deviceId: memberEnvelope.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
    } else if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({
        userId: memberEnvelope.sender_user_id,
        deviceId: memberEnvelope.sender_device_id,
      });
    }

    // Decrypt KEK from member envelope (worker uses identity ECDH private internally)
    await worker.decryptKekFromMemberEnvelope({
      encryptedKek: base64UrlDecode(memberEnvelope.encrypted_kek),
      nonce: base64UrlDecode(memberEnvelope.nonce),
      senderIdentityEcdhPublic: senderEcdhPk,
      workspaceId,
      targetUserId: userId,
      keyVersion: memberEnvelope.key_version,
      senderDeviceId: memberEnvelope.sender_device_id,
    });

    // Re-encrypt KEK for device envelope (worker uses device ECDH private internally)
    const pubKeys = await worker.getPublicKeys();
    const deviceEnvelope = await worker.encryptKekForDevice({
      workspaceId,
      userId,
      senderDeviceId: deviceId,
      targetDeviceId: deviceId,
      targetDeviceEcdhPublic: pubKeys.deviceEcdhPublic,
      keyVersion: memberEnvelope.key_version,
    });

    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: memberEnvelope.key_version,
      device_id: deviceId,
      sender_device_id: deviceId,
      encrypted_kek: base64UrlEncode(deviceEnvelope.encrypted),
      nonce: base64UrlEncode(deviceEnvelope.nonce),
    });

    // UMK backup
    const backup = await worker.wrapKekWithUmk({
      workspaceId,
      userId,
      keyVersion: memberEnvelope.key_version,
    });
    await encryptionApi.createKekBackupWithPop(workspaceId, {
      key_version: memberEnvelope.key_version,
      encrypted_kek: base64UrlEncode(backup.encrypted),
      nonce: base64UrlEncode(backup.nonce),
    });

    return "restored";
  }

  let backupData: { encrypted_kek: string; nonce: string; key_version: number } | null = null;
  try {
    backupData = await encryptionApi.getKekBackupWithPop(workspaceId);
  } catch {
    // No backup available
  }

  if (backupData) {
    // If backup exists but UMK decrypt fails, surface the error
    try {
      await worker.unwrapKekFromBackup({
        encryptedKek: base64UrlDecode(backupData.encrypted_kek),
        nonce: base64UrlDecode(backupData.nonce),
        workspaceId,
        userId,
        keyVersion: backupData.key_version,
      });
    } catch {
      throw new BackupDecryptError(workspaceId);
    }

    const pubKeys = await worker.getPublicKeys();
    const deviceEnvelope = await worker.encryptKekForDevice({
      workspaceId,
      userId,
      senderDeviceId: deviceId,
      targetDeviceId: deviceId,
      targetDeviceEcdhPublic: pubKeys.deviceEcdhPublic,
      keyVersion: backupData.key_version,
    });

    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: backupData.key_version,
      device_id: deviceId,
      sender_device_id: deviceId,
      encrypted_kek: base64UrlEncode(deviceEnvelope.encrypted),
      nonce: base64UrlEncode(deviceEnvelope.nonce),
    });

    return "restored";
  }

  // No member envelope and no backup: check if KEK already exists in workspace
  if (currentKekVersion > 0) return "needs_distribution";

  // Fresh workspace: generate new KEK (only succeeds for key_version 1, first creator)
  await worker.generateKek(workspaceId);

  const pubKeys = await worker.getPublicKeys();
  const freshEnvelope = await worker.encryptKekForDevice({
    workspaceId,
    userId,
    senderDeviceId: deviceId,
    targetDeviceId: deviceId,
    targetDeviceEcdhPublic: pubKeys.deviceEcdhPublic,
    keyVersion: 1,
  });

  const freshBackup = await worker.wrapKekWithUmk({
    workspaceId,
    userId,
    keyVersion: 1,
  });

  try {
    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: 1,
      device_id: deviceId,
      sender_device_id: deviceId,
      encrypted_kek: base64UrlEncode(freshEnvelope.encrypted),
      nonce: base64UrlEncode(freshEnvelope.nonce),
      is_active: true,
    });

    await encryptionApi.createKekBackupWithPop(workspaceId, {
      key_version: 1,
      encrypted_kek: base64UrlEncode(freshBackup.encrypted),
      nonce: base64UrlEncode(freshBackup.nonce),
    });

    return "restored";
  } catch {
    // 409 Conflict: KEK exists but not obtainable through any path
    return "needs_distribution";
  }
}

function getDeviceName(): string {
  const ua = navigator.userAgent;
  if (/Chrome/.test(ua)) return "Chrome";
  if (/Firefox/.test(ua)) return "Firefox";
  if (/Safari/.test(ua)) return "Safari";
  return "Browser";
}

function getDeviceType(): string {
  if (/Mobi|Android/i.test(navigator.userAgent)) return "mobile";
  return "desktop";
}
