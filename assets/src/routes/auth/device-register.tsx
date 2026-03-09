import { createSignal, onMount, onCleanup, Show, Match, Switch } from "solid-js";
import { useNavigate, A } from "@solidjs/router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { ShieldCheckIcon, AlertTriangleIcon } from "lucide-solid";
import { SafetyNumber } from "@/features/devices/safety-number";
import { authState, setFullSession, setDeviceState } from "@/shared/lib/auth-state";
import { authApi, devicesApi, trustTransferApi } from "@/shared/api";
import { persistDeviceId } from "@/features/auth";
import { persistDeviceKeysOnly, persistUmkForLogin, restoreSessionPdk, persistSessionPdk } from "@/features/auth/lib/key-persistence";
import {
  base64UrlEncode,
  base64UrlDecode,
  generateDeviceKeyPair,
  generateClientNonce,
  ecdhDecrypt,
  verifyTofu,
  handleTofuResult,
  decryptTrustState,
  deriveAuthKeys,
} from "@/shared/lib/crypto";
import { importTofuEntries } from "@/shared/lib/trust-store";
import { buildDeviceUmkDistributionAad } from "@/shared/lib/crypto/aad";

type Phase = "generating" | "waiting" | "restoring" | "done" | "error" | "expired" | "needs_password";

export default function DeviceRegisterPage() {
  const navigate = useNavigate();
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
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let eventSource: EventSource | undefined;
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;
  let nonceRefreshTimer: ReturnType<typeof setInterval> | undefined;

  onCleanup(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (eventSource) eventSource.close();
    if (expiryTimer) clearTimeout(expiryTimer);
    if (nonceRefreshTimer) clearInterval(nonceRefreshTimer);
  });

  onMount(async () => {
    const auth = authState();
    if (!auth) {
      navigate("/auth/login");
      return;
    }

    try {
      // Get identity signing public key from server
      const me = await authApi.me();

      if (!me.identity_signing_public_key) {
        throw new Error("Identity key not available");
      }
      setIdentitySigningPublic(base64UrlDecode(me.identity_signing_public_key));

      // Generate device keys and persist early (design: DSK early persistence)
      const keys = generateDeviceKeyPair();
      setDeviceKeys(keys);
      try {
        await persistDeviceKeysOnly(keys.ecdhPrivate, keys.signingPrivate, auth.user.id);
      } catch {
        // DSK unavailable and no in-memory PDK (e.g. page reload) — need password re-entry
        setPendingKeys(keys);
        setPhase("needs_password");
        return;
      }
      const nonce = generateClientNonce();
      setClientNonce(nonce);

      // Create pending device (2nd+ devices only)
      const res = await devicesApi.createPending({
        name: getDeviceName(),
        device_type: getDeviceType(),
        device_ecdh_public_key: base64UrlEncode(keys.ecdhPublic),
        device_signing_public_key: base64UrlEncode(keys.signingPublic),
        client_nonce: base64UrlEncode(nonce),
        identity_signing_public_key: base64UrlEncode(identitySigningPublic()!),
      });

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
            const status = await devicesApi.getPendingStatus(res.device_id);
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

      // SSE for approval notification
      try {
        eventSource = new EventSource(`/api/devices/pending/${res.device_id}/events`);
        eventSource.addEventListener("pending_approved", async () => {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          await handleApproved(res.device_id, keys);
        });
        eventSource.addEventListener("expired", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          setPhase("expired");
        });
        eventSource.addEventListener("pending_rejected", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          setError("Device registration was rejected by an existing device.");
          setPhase("error");
        });
        eventSource.onerror = () => {
          // SSE interrupted — start polling fallback
          if (eventSource) {
            eventSource.close();
            eventSource = undefined;
          }
          startPollingFallback();
        };
      } catch {
        // SSE not available — start polling fallback
        startPollingFallback();
      }

      // Expiry timer: pending devices have a 5-minute TTL
      expiryTimer = setTimeout(() => {
        if (phase() === "waiting") {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          setPhase("expired");
        }
      }, 5 * 60 * 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
      setPhase("error");
    }
  });

  const handlePdkReentry = async (e: Event) => {
    e.preventDefault();
    setPdkError(null);
    setPdkLoading(true);

    try {
      const auth = authState();
      if (!auth) throw new Error("No session");

      const keys = pendingKeys();
      if (!keys) throw new Error("No pending keys");

      const saltRes = await authApi.getSalt(auth.user.email);
      const derived = await deriveAuthKeys(pdkPassword(), saltRes.salt, saltRes.kdf_params);
      await authApi.verifyKey(derived.authKeyBase64);
      persistSessionPdk(derived.pdk);
      await persistDeviceKeysOnly(keys.ecdhPrivate, keys.signingPrivate, auth.user.id);

      // Resume the normal flow
      setDeviceKeys(keys);
      setPendingKeys(null);
      const nonce = generateClientNonce();
      setClientNonce(nonce);
      setPhase("generating");

      // Re-run the pending device creation (same as onMount continuation)
      const res = await devicesApi.createPending({
        name: getDeviceName(),
        device_type: getDeviceType(),
        device_ecdh_public_key: base64UrlEncode(keys.ecdhPublic),
        device_signing_public_key: base64UrlEncode(keys.signingPublic),
        client_nonce: base64UrlEncode(nonce),
        identity_signing_public_key: base64UrlEncode(identitySigningPublic()!),
      });

      setPendingDeviceId(res.device_id);
      setPhase("waiting");

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
            const status = await devicesApi.getPendingStatus(res.device_id);
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

      try {
        eventSource = new EventSource(`/api/devices/pending/${res.device_id}/events`);
        eventSource.addEventListener("pending_approved", async () => {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          await handleApproved(res.device_id, keys);
        });
        eventSource.addEventListener("expired", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          setPhase("expired");
        });
        eventSource.addEventListener("pending_rejected", () => {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          setError("Device registration was rejected by an existing device.");
          setPhase("error");
        });
        eventSource.onerror = () => {
          if (eventSource) {
            eventSource.close();
            eventSource = undefined;
          }
          startPollingFallback();
        };
      } catch {
        startPollingFallback();
      }

      expiryTimer = setTimeout(() => {
        if (phase() === "waiting") {
          if (eventSource) eventSource.close();
          if (pollTimer) clearInterval(pollTimer);
          setPhase("expired");
        }
      }, 5 * 60 * 1000);
    } catch (err) {
      setPdkError(err instanceof Error ? err.message : "Password verification failed");
    } finally {
      setPdkLoading(false);
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
        // identity_key_changed / ecdh_key_mismatch are hard failures per trust.md
        if (err instanceof Error && err.message.includes("key verification failed")) {
          throw err;
        }
        // Other failures (404, network, decryption) are best-effort per design
      }

      // Establish PoP credential before accessing PoP-required endpoints
      setDeviceState({
        deviceId,
        deviceEcdhPrivate: keys.ecdhPrivate,
        deviceSigningPrivate: keys.signingPrivate,
      });

      // Get UMK from server (distributed by existing device, PoP required)
      // Polling may report "approved" before UMK distribution completes, so retry
      const umkData = await retryGetUmk(deviceId, 10, 2000);

      // TOFU verification on UMK sender (design step 14)
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
      const senderEcdhPublic = base64UrlDecode(umkData.sender_ecdh_public_key);
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
        const { decryptIdentityPrivateKeys } = await import("@/shared/lib/crypto");
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

      setPhase("done");
      navigate("/");
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
            Verify this device from an existing device, or{" "}
            <A href="/auth/recovery" class="text-primary underline underline-offset-4">
              use your recovery key
            </A>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Switch>
            <Match when={phase() === "generating"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <Spinner class="size-6" />
                <p class="text-sm text-muted-foreground">Generating device keys...</p>
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
                <p class="text-sm text-muted-foreground">Restoring encryption keys...</p>
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
