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
import { authState, setFullSession, setDeviceState } from "@/shared/lib/auth-state";
import { authApi, devicesApi, encryptionApi, trustTransferApi } from "@/shared/api";
import { ApiError } from "@/shared/api/core";
import { persistDeviceId, persistDeviceKeysOnly, persistUmkForLogin, restoreSessionPdk, persistSessionPdk } from "@/features/auth";
import {
  base64UrlEncode,
  base64UrlDecode,
  generateDeviceKeyPair,
  generateClientNonce,
  signDeviceRegistration,
  ecdhDecrypt,
  verifyTofu,
  handleTofuResult,
  decryptTrustState,
  decryptIdentityPrivateKeys,
  deriveAuthKeys,
  decryptKekFromMemberEnvelope,
  unwrapKekFromBackup,
  encryptKekForDevice,
  wrapKekWithUmk,
  generateKek,
} from "@/shared/lib/crypto";
import type { IdentityKeyPair } from "@/shared/lib/crypto";
import { importTofuEntries } from "@/shared/lib/trust-store";
import { buildDeviceUmkDistributionAad } from "@/shared/lib/crypto/aad";

type Phase = "generating" | "waiting" | "restoring" | "done" | "error" | "expired" | "needs_password" | "reauth";

export default function DeviceRegisterPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const isRecoveryFromState = () => (location.state as Record<string, unknown>)?.recovery === true;
  const [phase, setPhase] = createSignal<Phase>("generating");
  const [error, setError] = createSignal<string | null>(null);
  const [deviceKeys, setDeviceKeys] = createSignal<{
    ecdhPrivate: Uint8Array;
    ecdhPublic: Uint8Array;
    signingPrivate: Uint8Array;
    signingPublic: Uint8Array;
  } | null>(null);
  const [clientNonce, setClientNonce] = createSignal<Uint8Array | null>(null);
  const [identitySigningPublic, setIdentitySigningPublic] = createSignal<Uint8Array | null>(null);
  const [, setPendingDeviceId] = createSignal<string | null>(null);
  const [, setTransferNonce] = createSignal<string | null>(null);
  const [pendingKeys, setPendingKeys] = createSignal<{
    ecdhPrivate: Uint8Array;
    ecdhPublic: Uint8Array;
    signingPrivate: Uint8Array;
    signingPublic: Uint8Array;
  } | null>(null);
  const [pdkPassword, setPdkPassword] = createSignal("");
  const [pdkLoading, setPdkLoading] = createSignal(false);
  const [pdkError, setPdkError] = createSignal<string | null>(null);
  const [statusMessage, setStatusMessage] = createSignal("");
  const [isRecoveryMode, setIsRecoveryMode] = createSignal(false);
  const [reauthPassword, setReauthPassword] = createSignal("");
  const [reauthLoading, setReauthLoading] = createSignal(false);
  const [reauthError, setReauthError] = createSignal<string | null>(null);
  const [reauthPendingKeys, setReauthPendingKeys] = createSignal<{
    ecdhPrivate: Uint8Array;
    ecdhPublic: Uint8Array;
    signingPrivate: Uint8Array;
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

    const keys = generateDeviceKeyPair();
    setDeviceKeys(keys);
    try {
      await persistDeviceKeysOnly(keys.ecdhPrivate, keys.signingPrivate, auth.user.id);
    } catch {
      setPendingKeys(keys);
      setPhase("needs_password");
      return;
    }

    await createRegistrationAndWait(keys);
  };

  // Create pending device and set up SSE/polling for approval
  const createRegistrationAndWait = async (
    keys: { ecdhPrivate: Uint8Array; ecdhPublic: Uint8Array; signingPrivate: Uint8Array; signingPublic: Uint8Array },
  ) => {
    const nonce = generateClientNonce();
    setClientNonce(nonce);

    let res;
    try {
      res = await devicesApi.createRegistration({
        name: getDeviceName(),
        device_type: getDeviceType(),
        device_ecdh_public_key: base64UrlEncode(keys.ecdhPublic),
        device_signing_public_key: base64UrlEncode(keys.signingPublic),
        client_nonce: base64UrlEncode(nonce),
        identity_signing_public_key: base64UrlEncode(identitySigningPublic()!),
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 403 && err.body?.error === "reauth_required") {
        setReauthPendingKeys(keys);
        setPhase("reauth");
        return;
      }
      throw err;
    }

    setPendingDeviceId(res.device_id);
    setPhase("waiting");

    // Request trust transfer nonce (best-effort, non-blocking)
    // Refresh every 4 minutes to stay within the 5-minute server TTL
    requestTrustTransferNonce(res.device_id);
    nonceRefreshTimer = setInterval(() => {
      if (phase() === "waiting") {
        requestTrustTransferNonce(res.device_id);
      }
    }, 4 * 60 * 1000);

    const startPollingFallback = () => {
      if (pollTimer) return;
      pollTimer = setInterval(async () => {
        try {
          const status = await devicesApi.getRegistrationSas(res.device_id);
          if (status.status === "approved") {
            if (pollTimer) clearInterval(pollTimer);
            await handleApproved(res.device_id, keys);
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
          if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
          await handleApproved(res.device_id, keys);
        });
        eventSource.addEventListener("expired", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
          setPhase("expired");
        });
        eventSource.addEventListener("pending_rejected", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
          setError("Device registration was rejected by an existing device.");
          setPhase("error");
        });
        eventSource.onopen = () => {
          if (pollTimer) { clearInterval(pollTimer); pollTimer = undefined; }
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
    const umk = auth.umk!;
    const identityKeys = auth.identityKeys!;
    const pdk = restoreSessionPdk() ?? undefined;

    setPhase("generating");
    setStatusMessage("Generating device keys\u2026");
    const keys = generateDeviceKeyPair();
    await persistDeviceKeysOnly(keys.ecdhPrivate, keys.signingPrivate, auth.user.id, pdk);

    setPhase("restoring");
    setStatusMessage("Registering device\u2026");

    const clientNonce = generateClientNonce();
    const deviceSignature = signDeviceRegistration(
      keys.signingPublic,
      keys.ecdhPublic,
      clientNonce,
      identityKeys.signingPrivate,
    );

    const pendingRes = await devicesApi.createRegistration({
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_ecdh_public_key: base64UrlEncode(keys.ecdhPublic),
      device_signing_public_key: base64UrlEncode(keys.signingPublic),
      client_nonce: base64UrlEncode(clientNonce),
      identity_signing_public_key: base64UrlEncode(identityKeys.signingPublic),
    });

    const approveRes = await devicesApi.approve(pendingRes.device_id, {
      identity_signature: base64UrlEncode(deviceSignature),
    });

    const deviceId = approveRes.device.id;

    persistDeviceId(deviceId);
    await persistUmkForLogin({
      umk,
      pdk,
      kmsi: false,
      userId: auth.user.id,
    });

    setFullSession(
      {
        user: auth.user,
        sessionId: auth.sessionId,
        umk,
        identityKeys,
        expiresAt: auth.expiresAt,
      },
      {
        deviceId,
        deviceEcdhPrivate: keys.ecdhPrivate,
        deviceSigningPrivate: keys.signingPrivate,
      },
    );

    setStatusMessage("Restoring workspace keys\u2026");
    const kekResults = await restoreWorkspaceKeks(
      auth.user.id,
      deviceId,
      umk,
      identityKeys,
      keys.ecdhPrivate,
      keys.ecdhPublic,
    );

    if (kekResults.backupDecryptFailed) {
      setPhase("error");
      setError("KEK backup decryption failed. This may indicate data corruption. Some workspaces may require key distribution from an existing device.");
      return;
    }

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
      const derived = await deriveAuthKeys(pdkPassword(), saltRes.salt, saltRes.kdf_params);
      await authApi.verifyKey(derived.authKeyBase64);
      persistSessionPdk(derived.pdk);

      const keys = pendingKeys();
      if (!keys) throw new Error("No pending keys");
      await persistDeviceKeysOnly(keys.ecdhPrivate, keys.signingPrivate, auth.user.id);
      setPendingKeys(null);
      setDeviceKeys(keys);
      await createRegistrationAndWait(keys);
    } catch (err) {
      setPdkError(err instanceof Error ? err.message : "Password verification failed");
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
      const derived = await deriveAuthKeys(reauthPassword(), saltRes.salt, saltRes.kdf_params);
      await authApi.verifyKey(derived.authKeyBase64);

      const keys = reauthPendingKeys();
      if (!keys) throw new Error("No pending keys");
      setReauthPendingKeys(null);
      await createRegistrationAndWait(keys);
    } catch (err) {
      setReauthError(err instanceof Error ? err.message : "Password verification failed");
    } finally {
      setReauthLoading(false);
    }
  };

  const requestTrustTransferNonce = async (deviceId: string) => {
    try {
      const res = await trustTransferApi.requestNonce(deviceId);
      setTransferNonce(res.nonce);
      sessionStorage.setItem(`refmd-transfer-nonce-${deviceId}`, res.nonce);
    } catch {
      // Best-effort: if nonce request fails, trust state transfer won't happen
    }
  };

  const handleApproved = async (
    deviceId: string,
    keys: { ecdhPrivate: Uint8Array; ecdhPublic: Uint8Array; signingPrivate: Uint8Array; signingPublic: Uint8Array },
  ) => {
    setPhase("restoring");
    const auth = authState();
    if (!auth) return;

    try {
      persistDeviceId(deviceId);

      // Trust state transfer retrieval (best-effort, BEFORE PoP binding)
      // Must happen before any PoP call because PoP auto-binds the session,
      // and trust-transfer endpoints reject bound sessions.
      try {
        await retrieveAndImportTrustState(
          auth.user.id,
          deviceId,
          keys.ecdhPrivate,
        );
      } catch (err) {
        // identity_key_changed / ecdh_key_mismatch are hard failures
        if (err instanceof Error && err.message.includes("key verification failed")) {
          throw err;
        }
        // Other failures (404, network, decryption) are best-effort
      }

      // Establish PoP credential before accessing PoP-required endpoints
      setDeviceState({
        deviceId,
        deviceEcdhPrivate: keys.ecdhPrivate,
        deviceSigningPrivate: keys.signingPrivate,
      });

      // Get UMK from server (distributed by existing device, PoP required)
      const umkData = await retryGetUmk(deviceId, 10, 2000);

      // TOFU verification on UMK sender
      if (!umkData.sender_signing_public_key || !umkData.sender_ecdh_public_key) {
        throw new Error("UMK response missing sender keys");
      }
      const senderSigningPk = base64UrlDecode(umkData.sender_signing_public_key);
      const senderEcdhPk = base64UrlDecode(umkData.sender_ecdh_public_key);
      const senderTofuResult = await verifyTofu(
        auth.user.id,
        umkData.sender_device_id,
        senderSigningPk,
        senderEcdhPk,
      );

      if (senderTofuResult.status === "identity_key_changed") {
        throw new Error("UMK sender identity key changed. This may indicate tampering.");
      }
      if (senderTofuResult.status === "ecdh_key_mismatch") {
        throw new Error("UMK sender ECDH key mismatch. This may indicate tampering.");
      }

      // Auto-trust sender for first_seen / update last_seen for known_trusted
      await handleTofuResult(senderTofuResult);

      // Decrypt UMK using ECDH
      const senderEcdhPublic = base64UrlDecode(umkData.sender_ecdh_public_key!);
      const aad = buildDeviceUmkDistributionAad(
        auth.user.id,
        umkData.sender_device_id,
        deviceId,
      );
      const umk = ecdhDecrypt(
        base64UrlDecode(umkData.encrypted_umk),
        base64UrlDecode(umkData.nonce),
        keys.ecdhPrivate,
        senderEcdhPublic,
        "device_umk_wrap",
        aad,
      );

      // Decrypt identity keys with UMK
      const me = await authApi.me();

      let identityKeys = null;
      if (me.keys) {
        identityKeys = decryptIdentityPrivateKeys(
          {
            encryptedEcdhPrivate: base64UrlDecode(me.keys.encrypted_ecdh_private),
            ecdhPrivateNonce: base64UrlDecode(me.keys.encrypted_ecdh_private_nonce),
            encryptedSigningPrivate: base64UrlDecode(me.keys.encrypted_signing_private),
            signingPrivateNonce: base64UrlDecode(me.keys.encrypted_signing_private_nonce),
          },
          umk,
          auth.user.id,
        );
      }

      // Persist UMK (KMSI-aware; device keys already persisted during registration)
      const pdk = restoreSessionPdk();
      await persistUmkForLogin({
        umk,
        pdk: pdk ?? undefined,
        kmsi: !!me.remember_me,
        userId: auth.user.id,
      });

      // Set full session
      setFullSession(
        {
          user: auth.user,
          sessionId: auth.sessionId,
          umk,
          identityKeys,
          expiresAt: auth.expiresAt,
        },
        {
          deviceId,
          deviceEcdhPrivate: keys.ecdhPrivate,
          deviceSigningPrivate: keys.signingPrivate,
        },
      );

      // Restore any workspace KEKs not distributed by the existing device (best-effort fallback)
      if (identityKeys) {
        try {
          await restoreWorkspaceKeks(
            auth.user.id,
            deviceId,
            umk,
            identityKeys,
            keys.ecdhPrivate,
            keys.ecdhPublic,
          );
        } catch {
          // KEK restoration is best-effort
        }
      }

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
            {isRecoveryMode()
              ? "Setting up your recovered device\u2026"
              : <>
                  Verify this device from an existing device, or{" "}
                  <A href="/auth/recovery" class="text-primary underline underline-offset-4">
                    use your recovery key
                  </A>.
                </>
            }
          </CardDescription>
        </CardHeader>
        <CardContent>
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

                <Show when={identitySigningPublic() && deviceKeys() && clientNonce()}>
                  <SafetyNumber
                    identitySigningPublic={identitySigningPublic()!}
                    deviceSigningPublic={deviceKeys()!.signingPublic}
                    deviceEcdhPublic={deviceKeys()!.ecdhPublic}
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
): Promise<Awaited<ReturnType<typeof devicesApi.getUmk>>> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      return await devicesApi.getUmk(deviceId);
    } catch (err) {
      if (i === maxAttempts - 1) throw err;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error("UMK retrieval failed after retries");
}

async function retrieveAndImportTrustState(
  userId: string,
  deviceId: string,
  deviceEcdhPrivate: Uint8Array,
): Promise<void> {
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

  // TOFU check: reject if sender keys have changed (indicates tampering).
  // first_seen is accepted because trust transfer is protected by AEAD + signature verification.
  const senderTofuResult = await verifyTofu(userId, state.sender_device_id, senderSigningPk, senderEcdhPublic);

  if (senderTofuResult.status === "identity_key_changed" || senderTofuResult.status === "ecdh_key_mismatch") {
    throw new Error("Trust state sender key verification failed");
  }

  // Verify transfer nonce
  const storedNonce = sessionStorage.getItem(`refmd-transfer-nonce-${deviceId}`);
  if (!storedNonce) return;

  const expectedNonce = base64UrlDecode(storedNonce);

  // Decrypt and verify trust state (signature + AEAD + nonce verification)
  // TOFU persistence is deferred until after cryptographic verification succeeds
  const snapshot = decryptTrustState(
    {
      encryptedState: base64UrlDecode(state.ciphertext),
      nonce: base64UrlDecode(state.nonce),
      signature: base64UrlDecode(state.signature),
    },
    deviceEcdhPrivate,
    senderEcdhPublic,
    senderSigningPk,
    expectedNonce,
    {
      userId,
      senderDeviceId: state.sender_device_id,
      targetDeviceId: deviceId,
    },
  );

  // Persist TOFU only after cryptographic verification succeeded
  await handleTofuResult(senderTofuResult);
  await importTofuEntries(snapshot.tofuEntries);
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

async function restoreWorkspaceKeks(
  userId: string,
  deviceId: string,
  umk: Uint8Array,
  identityKeys: IdentityKeyPair,
  deviceEcdhPrivate: Uint8Array,
  deviceEcdhPublic: Uint8Array,
): Promise<KekRestoreResults> {
  const result: KekRestoreResults = { needsDistribution: [], backupDecryptFailed: false };
  const { workspace_ids } = await encryptionApi.getWorkspaceIds();

  for (const workspaceId of workspace_ids) {
    try {
      const status = await restoreKekForWorkspace(
        workspaceId,
        userId,
        deviceId,
        umk,
        identityKeys,
        deviceEcdhPrivate,
        deviceEcdhPublic,
      );
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
  umk: Uint8Array,
  identityKeys: IdentityKeyPair,
  deviceEcdhPrivate: Uint8Array,
  deviceEcdhPublic: Uint8Array,
): Promise<"restored" | "needs_distribution"> {
  let currentKekVersion = 0;
  try {
    const existing = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId);
    if (existing.keys.length > 0) return "restored";
    currentKekVersion = existing.current_kek_version;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      currentKekVersion = (e.body.details as { current_kek_version?: number })?.current_kek_version ?? 0;
    } else {
      throw e;
    }
  }

  const memberEnvelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (memberEnvelope && memberEnvelope.sender_ecdh_public_key && memberEnvelope.sender_signing_public_key) {
    const senderEcdhPk = base64UrlDecode(memberEnvelope.sender_ecdh_public_key);
    const senderSigningPk = base64UrlDecode(memberEnvelope.sender_signing_public_key);

    const tofuResult = await verifyTofu(memberEnvelope.sender_user_id, memberEnvelope.sender_device_id, senderSigningPk, senderEcdhPk);
    if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
      throw new Error("Key verification failed for member envelope sender. Aborting KEK recovery.");
    }
    await handleTofuResult(tofuResult);

    const kek = decryptKekFromMemberEnvelope(
      base64UrlDecode(memberEnvelope.encrypted_kek),
      base64UrlDecode(memberEnvelope.nonce),
      identityKeys.ecdhPrivate,
      senderEcdhPk,
      workspaceId,
      userId,
      memberEnvelope.key_version,
      memberEnvelope.sender_device_id,
    );

    const deviceEnvelope = encryptKekForDevice(
      kek,
      deviceEcdhPrivate,
      deviceEcdhPublic,
      workspaceId,
      userId,
      deviceId,
      deviceId,
      memberEnvelope.key_version,
    );

    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: memberEnvelope.key_version,
      device_id: deviceId,
      sender_device_id: deviceId,
      encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
      nonce: base64UrlEncode(deviceEnvelope.nonce),
    });

    const backup = wrapKekWithUmk(kek, umk, workspaceId, userId, memberEnvelope.key_version);
    await encryptionApi.createKekBackupWithPop(workspaceId, {
      key_version: memberEnvelope.key_version,
      encrypted_kek: base64UrlEncode(backup.encryptedKek),
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
    let kek: Uint8Array;
    try {
      kek = unwrapKekFromBackup(
        base64UrlDecode(backupData.encrypted_kek),
        base64UrlDecode(backupData.nonce),
        umk,
        workspaceId,
        userId,
        backupData.key_version,
      );
    } catch {
      throw new BackupDecryptError(workspaceId);
    }

    const deviceEnvelope = encryptKekForDevice(
      kek,
      deviceEcdhPrivate,
      deviceEcdhPublic,
      workspaceId,
      userId,
      deviceId,
      deviceId,
      backupData.key_version,
    );

    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: backupData.key_version,
      device_id: deviceId,
      sender_device_id: deviceId,
      encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
      nonce: base64UrlEncode(deviceEnvelope.nonce),
    });

    return "restored";
  }

  // No member envelope and no backup: check if KEK already exists in workspace
  if (currentKekVersion > 0) return "needs_distribution";

  // Fresh workspace: generate new KEK (only succeeds for key_version 1, first creator)
  const freshKek = generateKek();
  const freshEnvelope = encryptKekForDevice(
    freshKek,
    deviceEcdhPrivate,
    deviceEcdhPublic,
    workspaceId,
    userId,
    deviceId,
    deviceId,
    1,
  );

  const freshBackup = wrapKekWithUmk(freshKek, umk, workspaceId, userId, 1);

  try {
    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: 1,
      device_id: deviceId,
      sender_device_id: deviceId,
      encrypted_kek: base64UrlEncode(freshEnvelope.ciphertext),
      nonce: base64UrlEncode(freshEnvelope.nonce),
      is_active: true,
    });

    await encryptionApi.createKekBackupWithPop(workspaceId, {
      key_version: 1,
      encrypted_kek: base64UrlEncode(freshBackup.encryptedKek),
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
