import { onMount, onCleanup, createEffect, createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { workspacesApi, encryptionApi, ApiError } from "@/shared/api";
import { authState, deviceState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

const TOKEN_SESSION_KEY = "refmd_invite_token";
const KEK_SAVE_MAX_RETRIES = 3;

async function retryAsync<T>(fn: () => Promise<T>, retries: number): Promise<T> {
  let lastError: unknown;
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

async function decryptKek(
  acceptResult: {
    encrypted_kek: string;
    kek_nonce: string;
    workspace_id: string;
    invitation_id: string;
    kek_version: number;
  },
  tokenBytes: Uint8Array,
): Promise<void> {
  const worker = getCryptoWorker();
  await worker.decryptKekFromInvitation({
    encryptedKek: base64UrlDecode(acceptResult.encrypted_kek),
    nonce: base64UrlDecode(acceptResult.kek_nonce),
    token: tokenBytes,
    workspaceId: acceptResult.workspace_id,
    invitationId: acceptResult.invitation_id,
    keyVersion: acceptResult.kek_version,
  });
}

async function saveDeviceEnvelope(
  acceptResult: { workspace_id: string; kek_version: number },
  auth: { user: { id: string } },
  device: { deviceId: string; deviceEcdhPublic: Uint8Array | null },
): Promise<void> {
  const worker = getCryptoWorker();
  if (!device.deviceEcdhPublic) throw new Error("Device ECDH public key not available");

  const encrypted = await worker.encryptKekForDevice({
    workspaceId: acceptResult.workspace_id,
    userId: auth.user.id,
    senderDeviceId: device.deviceId,
    targetDeviceId: device.deviceId,
    targetDeviceEcdhPublic: device.deviceEcdhPublic,
    keyVersion: acceptResult.kek_version,
  });

  try {
    await encryptionApi.createWorkspaceKeyWithPop(acceptResult.workspace_id, {
      device_id: device.deviceId,
      sender_device_id: device.deviceId,
      encrypted_kek: base64UrlEncode(encrypted.encrypted),
      nonce: base64UrlEncode(encrypted.nonce),
      key_version: acceptResult.kek_version,
    });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 409)) throw e;
  }
}

async function saveUmkBackup(
  acceptResult: { workspace_id: string; kek_version: number },
  auth: { user: { id: string } },
): Promise<void> {
  const worker = getCryptoWorker();
  const backup = await worker.wrapKekWithUmk({
    workspaceId: acceptResult.workspace_id,
    userId: auth.user.id,
    keyVersion: acceptResult.kek_version,
  });

  try {
    await encryptionApi.createKekBackupWithPop(acceptResult.workspace_id, {
      encrypted_kek: base64UrlEncode(backup.encrypted),
      nonce: base64UrlEncode(backup.nonce),
      key_version: acceptResult.kek_version,
    });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 409)) throw e;
  }
}

async function recoverFromMemberEnvelope(
  workspaceId: string,
  auth: NonNullable<ReturnType<typeof authState>>,
  device: { deviceId: string; deviceEcdhPublic: Uint8Array | null },
): Promise<void> {
  if (!auth.identityEcdhPublic) {
    throw new Error("Identity keys not available for KEK recovery.");
  }

  const worker = getCryptoWorker();
  const envelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (!envelope || !envelope.sender_ecdh_public_key || !envelope.sender_signing_public_key) {
    throw new Error(
      "Encryption key recovery is not yet available. A workspace administrator needs to complete key rotation first.",
    );
  }

  const senderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
  const senderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);

  const tofuResult = await worker.tofuVerify({
    userId: envelope.sender_user_id,
    deviceId: envelope.sender_device_id,
    signingPublicKey: senderSigningPk,
    ecdhPublicKey: senderEcdhPk,
  });
  if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
    throw new Error("Key verification failed for member envelope sender.");
  }
  if (tofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId: envelope.sender_user_id,
      deviceId: envelope.sender_device_id,
      signingPublicKey: senderSigningPk,
      ecdhPublicKey: senderEcdhPk,
    });
  } else if (tofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: envelope.sender_user_id,
      deviceId: envelope.sender_device_id,
    });
  }

  // Decrypt KEK from member envelope (worker uses identity ECDH private internally)
  await worker.decryptKekFromMemberEnvelope({
    encryptedKek: base64UrlDecode(envelope.encrypted_kek),
    nonce: base64UrlDecode(envelope.nonce),
    senderIdentityEcdhPublic: senderEcdhPk,
    workspaceId,
    targetUserId: auth.user.id,
    keyVersion: envelope.key_version,
    senderDeviceId: envelope.sender_device_id,
  });

  if (!device.deviceEcdhPublic) throw new Error("Device ECDH public key not available");
  const deviceEnvelope = await worker.encryptKekForDevice({
    workspaceId,
    userId: auth.user.id,
    senderDeviceId: device.deviceId,
    targetDeviceId: device.deviceId,
    targetDeviceEcdhPublic: device.deviceEcdhPublic,
    keyVersion: envelope.key_version,
  });

  try {
    await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
      key_version: envelope.key_version,
      device_id: device.deviceId,
      sender_device_id: device.deviceId,
      encrypted_kek: base64UrlEncode(deviceEnvelope.encrypted),
      nonce: base64UrlEncode(deviceEnvelope.nonce),
    });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 409)) throw e;
  }

  const backup = await worker.wrapKekWithUmk({
    workspaceId,
    userId: auth.user.id,
    keyVersion: envelope.key_version,
  });
  try {
    await encryptionApi.createKekBackupWithPop(workspaceId, {
      key_version: envelope.key_version,
      encrypted_kek: base64UrlEncode(backup.encrypted),
      nonce: base64UrlEncode(backup.nonce),
    });
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 409)) throw e;
  }
}

export default function InvitePage() {
  const navigate = useNavigate();
  const [status, setStatus] = createSignal<
    | "loading"
    | "need_auth"
    | "confirm"
    | "accepting"
    | "saving_keys"
    | "success"
    | "partial"
    | "error"
  >("loading");
  const [error, setError] = createSignal<string | null>(null);
  const [retryable, setRetryable] = createSignal(false);
  const [kekWarning, setKekWarning] = createSignal<string | null>(null);
  const [result, setResult] = createSignal<{
    workspace_id: string;
    workspace_name: string;
    role_name: string | null;
  } | null>(null);
  let redirectTimer: ReturnType<typeof setTimeout> | undefined;
  onCleanup(() => {
    if (redirectTimer) clearTimeout(redirectTimer);
  });

  const trySaves = async (
    acceptResult: { workspace_id: string; kek_version: number },
    auth: NonNullable<ReturnType<typeof authState>>,
    device: NonNullable<ReturnType<typeof deviceState>>,
    deviceSaved: boolean,
    umkSaved: boolean,
  ): Promise<{ deviceSaved: boolean; umkSaved: boolean }> => {
    if (!deviceSaved) {
      try {
        await retryAsync(
          () =>
            saveDeviceEnvelope(acceptResult, auth, {
              deviceId: device.deviceId,
              deviceEcdhPublic: device.deviceEcdhPublic,
            }),
          KEK_SAVE_MAX_RETRIES,
        );
        deviceSaved = true;
      } catch {
        // Retries exhausted for device envelope
      }
    }

    if (!umkSaved) {
      try {
        await retryAsync(
          () => saveUmkBackup(acceptResult, { user: auth.user }),
          KEK_SAVE_MAX_RETRIES,
        );
        umkSaved = true;
      } catch {
        // Retries exhausted for UMK backup
      }
    }

    return { deviceSaved, umkSaved };
  };

  const acceptAndPersistKek = async (
    token: string,
    auth: NonNullable<ReturnType<typeof authState>>,
    device: NonNullable<ReturnType<typeof deviceState>>,
  ) => {
    const tokenBytes = base64UrlDecode(token);
    const maxAcceptAttempts = 2;
    let savedWorkspaceId: string | null = null;
    let lastAcceptResult: { workspace_id: string; kek_version: number } | undefined;
    let kekDecrypted = false;
    let deviceSaved = false;
    let umkSaved = false;

    for (let attempt = 0; attempt < maxAcceptAttempts; attempt++) {
      let acceptResult;
      try {
        acceptResult = await workspacesApi.acceptInvitation(token);
      } catch (err) {
        if (
          err instanceof ApiError &&
          err.status === 410 &&
          err.body.error === "invitation_kek_outdated"
        ) {
          const bodyWsId = typeof err.body.workspace_id === "string" ? err.body.workspace_id : null;
          const recoveryWorkspaceId = savedWorkspaceId || bodyWsId;
          if (recoveryWorkspaceId) {
            try {
              await recoverFromMemberEnvelope(recoveryWorkspaceId, auth, {
                deviceId: device.deviceId,
                deviceEcdhPublic: device.deviceEcdhPublic,
              });
              sessionStorage.removeItem(TOKEN_SESSION_KEY);
              setStatus("success");
              return;
            } catch {
              // Member envelope not available (new member or rotation not yet complete)
            }
          }
          throw new Error(
            "This invitation uses an outdated encryption key. Please request a new invitation from the workspace administrator.",
          );
        }
        if (
          err instanceof ApiError &&
          err.status === 409 &&
          err.body.error === "kek_rotation_in_progress"
        ) {
          if (savedWorkspaceId) {
            setStatus("partial");
            setKekWarning(
              "A key rotation is currently in progress for this workspace. Please try again after the rotation is complete, or go to your dashboard where key distribution will happen automatically.",
            );
          } else {
            setStatus("partial");
            setKekWarning(
              "A key rotation is currently in progress for this workspace. Please try again after the rotation is complete, or request a new invitation from the workspace administrator.",
            );
          }
          return;
        }
        throw err;
      }

      savedWorkspaceId = acceptResult.workspace_id;

      if (attempt === 0) {
        setResult({
          workspace_id: acceptResult.workspace_id,
          workspace_name: acceptResult.workspace_name,
          role_name: acceptResult.role_name ?? null,
        });
      }

      try {
        await decryptKek(acceptResult, tokenBytes);
        kekDecrypted = true;
      } catch {
        throw new Error("KEK decryption failed. Please request a new invitation link.");
      }
      lastAcceptResult = acceptResult;

      setStatus("saving_keys");
      const saves = await trySaves(acceptResult, auth, device, deviceSaved, umkSaved);
      deviceSaved = saves.deviceSaved;
      umkSaved = saves.umkSaved;

      if (deviceSaved && umkSaved) {
        sessionStorage.removeItem(TOKEN_SESSION_KEY);
        setStatus("success");
        return;
      }

      if (deviceSaved || umkSaved) {
        // At least one save succeeded — do not re-accept (design: re-accept only when ALL fail)
        break;
      }

      // Both saves failed; re-accept to re-obtain encrypted_kek (idempotent)
    }

    // Retry failed saves with KEK still in worker (design: keep KEK until both complete)
    if (kekDecrypted && lastAcceptResult && !(deviceSaved && umkSaved)) {
      const saves = await trySaves(lastAcceptResult, auth, device, deviceSaved, umkSaved);
      deviceSaved = saves.deviceSaved;
      umkSaved = saves.umkSaved;

      if (deviceSaved && umkSaved) {
        sessionStorage.removeItem(TOKEN_SESSION_KEY);
        setStatus("success");
        return;
      }
    }

    // All attempts exhausted — membership created but KEK persistence incomplete
    setStatus("partial");
    setKekWarning(
      "You have joined the workspace, but encryption key setup is incomplete. You can retry now, or contact a workspace administrator to receive a new invitation.",
    );
  };

  onMount(async () => {
    const hash = window.location.hash;
    let token: string | null = null;

    if (hash.startsWith("#token=")) {
      token = hash.slice("#token=".length);
      sessionStorage.setItem(TOKEN_SESSION_KEY, token);
      history.replaceState(null, "", window.location.pathname);
    } else {
      token = sessionStorage.getItem(TOKEN_SESSION_KEY);
    }

    if (!token) {
      setError("No invitation token found.");
      setStatus("error");
      return;
    }

    const auth = authState();
    if (!auth) {
      setStatus("need_auth");
      return;
    }

    const device = deviceState();
    if (!device) {
      navigate("/devices/register");
      return;
    }

    if (!cryptoWorkerReady()) {
      if (auth.needsPasswordReentry) return;
      navigate("/devices/register");
      return;
    }

    setStatus("confirm");
  });

  const startAccept = () => {
    const token = sessionStorage.getItem(TOKEN_SESSION_KEY);
    const auth = authState();
    const device = deviceState();
    if (!token || !auth || !device || !cryptoWorkerReady()) return;

    setStatus("accepting");
    acceptAndPersistKek(token, auth, device).catch((err) => {
      setError(err instanceof Error ? err.message : "Failed to accept invitation");
      const isApiErr = err instanceof ApiError;
      setRetryable(!isApiErr || (isApiErr && err.status >= 500));
      setStatus("error");
    });
  };

  createEffect(() => {
    const s = status();
    if (s !== "loading" && s !== "need_auth") return;
    const auth = authState();
    const device = deviceState();
    if (!auth || !device || !cryptoWorkerReady()) return;

    setStatus("confirm");
  });

  const navigateToWorkspace = () => {
    const r = result();
    if (r?.workspace_id) {
      setCurrentWorkspaceId(r.workspace_id);
    }
    navigate("/dashboard");
  };

  createEffect(() => {
    if (status() !== "success") return;
    redirectTimer = setTimeout(navigateToWorkspace, 2000);
  });

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      {/* Unauthenticated landing */}
      <Show when={status() === "need_auth"}>
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1 text-center">
            <CardTitle class="text-2xl font-bold">You've been invited</CardTitle>
            <CardDescription>
              Someone invited you to collaborate on a workspace. Create an account or sign in to
              accept.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <Button class="w-full" onClick={() => navigate("/auth/register")}>
              Create Account
            </Button>
            <Button variant="outline" class="w-full" onClick={() => navigate("/auth/login")}>
              Sign In
            </Button>
          </CardContent>
        </Card>
      </Show>

      {/* Authenticated confirmation */}
      <Show when={status() === "confirm"}>
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1 text-center">
            <CardTitle class="text-2xl font-bold">Accept Invitation</CardTitle>
            <CardDescription>
              Accept this workspace invitation as{" "}
              <span class="font-medium text-foreground">{authState()?.user.email}</span>?
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <Button class="w-full" onClick={startAccept}>
              Accept Invitation
            </Button>
            <Button
              variant="outline"
              class="w-full"
              onClick={() => {
                sessionStorage.removeItem(TOKEN_SESSION_KEY);
                navigate("/dashboard");
              }}
            >
              Decline
            </Button>
          </CardContent>
        </Card>
      </Show>

      {/* Processing states */}
      <Show when={status() === "loading" || status() === "accepting" || status() === "saving_keys"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <Spinner class="size-8 mx-auto" />
          <p class="text-muted-foreground">
            {status() === "loading"
              ? "Processing invitation..."
              : status() === "accepting"
                ? "Accepting invitation..."
                : "Setting up workspace encryption..."}
          </p>
        </div>
      </Show>

      {/* Success */}
      <Show when={status() === "success"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <p class="text-foreground font-medium">You've joined the workspace!</p>
          <Show when={result()}>
            {(r) => (
              <p class="text-muted-foreground">
                <span class="font-medium text-foreground">{r().workspace_name}</span>
                <Show when={r().role_name}>
                  {(role) => (
                    <span>
                      {" "}
                      as <span class="font-medium text-foreground">{role()}</span>
                    </span>
                  )}
                </Show>
              </p>
            )}
          </Show>
          <p class="text-sm text-muted-foreground">Redirecting to workspace...</p>
          <Button variant="outline" class="w-full" onClick={navigateToWorkspace}>
            Go to Workspace
          </Button>
        </div>
      </Show>

      {/* Partial — KEK setup incomplete */}
      <Show when={status() === "partial"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <p class="text-foreground font-medium">Key Setup Incomplete</p>
          <p class="text-sm text-muted-foreground">{kekWarning()}</p>
          <div class="flex gap-2 justify-center">
            <Button
              onClick={() => {
                const token = sessionStorage.getItem(TOKEN_SESSION_KEY);
                if (token) {
                  setStatus("accepting");
                  setKekWarning(null);
                  const auth = authState();
                  const device = deviceState();
                  if (auth && device && cryptoWorkerReady()) {
                    acceptAndPersistKek(token, auth, device).catch((err) => {
                      setError(err instanceof Error ? err.message : "Retry failed");
                      setStatus("error");
                    });
                  }
                }
              }}
            >
              Retry
            </Button>
            <Button variant="outline" onClick={() => navigate("/dashboard")}>
              Go to Dashboard
            </Button>
          </div>
        </div>
      </Show>

      {/* Error */}
      <Show when={status() === "error"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <p class="text-destructive font-medium">{error()}</p>
          <div class="flex gap-2 justify-center">
            <Show when={retryable()}>
              <Button
                onClick={() => {
                  const token = sessionStorage.getItem(TOKEN_SESSION_KEY);
                  if (token) {
                    setRetryable(false);
                    setError(null);
                    setStatus("accepting");
                    const auth = authState();
                    const device = deviceState();
                    if (auth && device && cryptoWorkerReady()) {
                      acceptAndPersistKek(token, auth, device).catch((err) => {
                        setError(err instanceof Error ? err.message : "Retry failed");
                        setStatus("error");
                      });
                    }
                  }
                }}
              >
                Retry
              </Button>
            </Show>
            <Button
              variant="outline"
              onClick={() => {
                sessionStorage.removeItem(TOKEN_SESSION_KEY);
                navigate("/dashboard");
              }}
            >
              Go to Dashboard
            </Button>
          </div>
        </div>
      </Show>
    </main>
  );
}
