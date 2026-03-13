import { onMount, onCleanup, createEffect, createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/shared/ui/card";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { workspacesApi, encryptionApi, ApiError } from "@/shared/api";
import { authState, deviceState } from "@/shared/lib/auth-state";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import {
  base64UrlDecode,
  base64UrlEncode,
  decryptKekFromInvitation,
  decryptKekFromMemberEnvelope,
  encryptKekForDevice,
  wrapKekWithUmk,
  verifyTofu,
  handleTofuResult,
} from "@/shared/lib/crypto";

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

function decryptKek(
  acceptResult: { encrypted_kek: string; kek_nonce: string; workspace_id: string; invitation_id: string; kek_version: number },
  tokenBytes: Uint8Array,
): Uint8Array {
  return decryptKekFromInvitation(
    base64UrlDecode(acceptResult.encrypted_kek),
    base64UrlDecode(acceptResult.kek_nonce),
    tokenBytes,
    acceptResult.workspace_id,
    acceptResult.invitation_id,
    acceptResult.kek_version,
  );
}

async function saveDeviceEnvelope(
  kek: Uint8Array,
  acceptResult: { workspace_id: string; kek_version: number },
  auth: { user: { id: string } },
  device: { deviceId: string; deviceEcdhPrivate: Uint8Array },
): Promise<void> {
  const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
  const { ciphertext, nonce } = encryptKekForDevice(
    kek,
    device.deviceEcdhPrivate,
    deviceEcdhPublic,
    acceptResult.workspace_id,
    auth.user.id,
    device.deviceId,
    device.deviceId,
    acceptResult.kek_version,
  );

  await encryptionApi.createWorkspaceKeyWithPop(acceptResult.workspace_id, {
    device_id: device.deviceId,
    sender_device_id: device.deviceId,
    encrypted_kek: base64UrlEncode(ciphertext),
    nonce: base64UrlEncode(nonce),
    key_version: acceptResult.kek_version,
  });
}

async function saveUmkBackup(
  kek: Uint8Array,
  acceptResult: { workspace_id: string; kek_version: number },
  auth: { user: { id: string }; umk: Uint8Array },
): Promise<void> {
  const { encryptedKek, nonce } = wrapKekWithUmk(
    kek,
    auth.umk,
    acceptResult.workspace_id,
    auth.user.id,
    acceptResult.kek_version,
  );

  await encryptionApi.createKekBackupWithPop(acceptResult.workspace_id, {
    encrypted_kek: base64UrlEncode(encryptedKek),
    nonce: base64UrlEncode(nonce),
    key_version: acceptResult.kek_version,
  });
}

async function recoverFromMemberEnvelope(
  workspaceId: string,
  auth: NonNullable<ReturnType<typeof authState>>,
  device: { deviceId: string; deviceEcdhPrivate: Uint8Array },
): Promise<void> {
  if (!auth.identityKeys) {
    throw new Error("Identity keys not available for KEK recovery.");
  }

  const envelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (!envelope || !envelope.sender_ecdh_public_key || !envelope.sender_signing_public_key) {
    throw new Error(
      "Encryption key recovery is not yet available. A workspace administrator needs to complete key rotation first.",
    );
  }

  const senderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
  const senderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);

  const tofuResult = await verifyTofu(
    envelope.sender_user_id,
    envelope.sender_device_id,
    senderSigningPk,
    senderEcdhPk,
  );
  if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
    throw new Error("Key verification failed for member envelope sender.");
  }
  await handleTofuResult(tofuResult);

  const kek = decryptKekFromMemberEnvelope(
    base64UrlDecode(envelope.encrypted_kek),
    base64UrlDecode(envelope.nonce),
    auth.identityKeys.ecdhPrivate,
    senderEcdhPk,
    workspaceId,
    auth.user.id,
    envelope.key_version,
    envelope.sender_device_id,
  );

  const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
  const deviceEnvelope = encryptKekForDevice(
    kek,
    device.deviceEcdhPrivate,
    deviceEcdhPublic,
    workspaceId,
    auth.user.id,
    device.deviceId,
    device.deviceId,
    envelope.key_version,
  );

  await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
    key_version: envelope.key_version,
    device_id: device.deviceId,
    sender_device_id: device.deviceId,
    encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
    nonce: base64UrlEncode(deviceEnvelope.nonce),
  });

  if (auth.umk) {
    const backup = wrapKekWithUmk(kek, auth.umk, workspaceId, auth.user.id, envelope.key_version);
    await encryptionApi.createKekBackupWithPop(workspaceId, {
      key_version: envelope.key_version,
      encrypted_kek: base64UrlEncode(backup.encryptedKek),
      nonce: base64UrlEncode(backup.nonce),
    });
  }
}

export default function InvitePage() {
  const navigate = useNavigate();
  const [status, setStatus] = createSignal<
    "loading" | "need_auth" | "confirm" | "accepting" | "saving_keys" | "success" | "partial" | "error"
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
  onCleanup(() => { if (redirectTimer) clearTimeout(redirectTimer); });

  const trySaves = async (
    kek: Uint8Array,
    acceptResult: { workspace_id: string; kek_version: number },
    auth: NonNullable<ReturnType<typeof authState>>,
    device: NonNullable<ReturnType<typeof deviceState>>,
    deviceSaved: boolean,
    umkSaved: boolean,
  ): Promise<{ deviceSaved: boolean; umkSaved: boolean }> => {
    if (!deviceSaved) {
      try {
        await retryAsync(
          () => saveDeviceEnvelope(kek, acceptResult, auth, {
            deviceId: device.deviceId,
            deviceEcdhPrivate: device.deviceEcdhPrivate!,
          }),
          KEK_SAVE_MAX_RETRIES,
        );
        deviceSaved = true;
      } catch {
        // Retries exhausted for device envelope
      }
    }

    if (!umkSaved && auth.umk) {
      try {
        await retryAsync(
          () => saveUmkBackup(kek, acceptResult, {
            user: auth.user,
            umk: auth.umk!,
          }),
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
    let lastKek: Uint8Array | undefined;
    let lastAcceptResult: { workspace_id: string; kek_version: number } | undefined;
    let deviceSaved = false;
    let umkSaved = false;

    for (let attempt = 0; attempt < maxAcceptAttempts; attempt++) {
      let acceptResult;
      try {
        acceptResult = await workspacesApi.acceptInvitation(token);
      } catch (err) {
        if (err instanceof ApiError && err.status === 410 &&
            err.body.error === "invitation_kek_outdated") {
          const bodyWsId = typeof err.body.workspace_id === "string" ? err.body.workspace_id : null;
          const recoveryWorkspaceId = savedWorkspaceId || bodyWsId;
          if (recoveryWorkspaceId) {
            try {
              await recoverFromMemberEnvelope(recoveryWorkspaceId, auth, {
                deviceId: device.deviceId,
                deviceEcdhPrivate: device.deviceEcdhPrivate!,
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
        if (err instanceof ApiError && err.status === 409 &&
            err.body.error === "kek_rotation_in_progress") {
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
        lastKek = decryptKek(acceptResult, tokenBytes);
      } catch {
        throw new Error("KEK decryption failed. Please request a new invitation link.");
      }
      lastAcceptResult = acceptResult;

      setStatus("saving_keys");
      const saves = await trySaves(lastKek, acceptResult, auth, device, deviceSaved, umkSaved);
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

    // Retry failed saves with KEK still in memory (design: keep KEK until both complete)
    if (lastKek && lastAcceptResult && !(deviceSaved && umkSaved)) {
      const saves = await trySaves(lastKek, lastAcceptResult, auth, device, deviceSaved, umkSaved);
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

    if (!device.deviceSigningPrivate) {
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
    if (!token || !auth || !device?.deviceSigningPrivate) return;

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
    if (!auth || !device?.deviceSigningPrivate) return;

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
            <CardTitle class="text-2xl font-bold">
              You've been invited
            </CardTitle>
            <CardDescription>
              Someone invited you to collaborate on a workspace.
              Create an account or sign in to accept.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <Button
              class="w-full"
              onClick={() => navigate("/auth/register")}
            >
              Create Account
            </Button>
            <Button
              variant="outline"
              class="w-full"
              onClick={() => navigate("/auth/login")}
            >
              Sign In
            </Button>
          </CardContent>
        </Card>
      </Show>

      {/* Authenticated confirmation */}
      <Show when={status() === "confirm"}>
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1 text-center">
            <CardTitle class="text-2xl font-bold">
              Accept Invitation
            </CardTitle>
            <CardDescription>
              Accept this workspace invitation as{" "}
              <span class="font-medium text-foreground">
                {authState()?.user.email}
              </span>
              ?
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
                      {" "}as <span class="font-medium text-foreground">{role()}</span>
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
                  if (auth && device && device.deviceSigningPrivate) {
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
                    if (auth && device && device.deviceSigningPrivate) {
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
