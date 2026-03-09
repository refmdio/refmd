import { createSignal, Show, Switch, Match, For, onCleanup } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";
import { KeyRoundIcon, AlertTriangleIcon, UploadIcon, CheckCircleIcon } from "lucide-solid";
import { authState, setFullSession } from "@/shared/lib/auth-state";
import { authApi, devicesApi, encryptionApi } from "@/shared/api";
import { persistDeviceId, persistDeviceKeysOnly, persistUmkForLogin, persistSessionPdk, restoreSessionPdk } from "@/features/auth";
import { parseRecoveryKeyFile } from "@/shared/lib/recovery-key-format";
import {
  base64UrlEncode,
  base64UrlDecode,
  randomBytes,
  deriveAuthKeys,
  deriveRukFromMnemonic,
  unwrapUmkWithRuk,
  decryptIdentityPrivateKeys,
  sign,
  wrapUmk,
  generateDeviceKeyPair,
  generateClientNonce,
  signDeviceRegistration,
  generateKek,
  decryptKekFromMemberEnvelope,
  unwrapKekFromBackup,
  encryptKekForDevice,
  wrapKekWithUmk,
  verifyTofu,
  handleTofuResult,
  isValidMnemonic,
} from "@/shared/lib/crypto";
import type { IdentityKeyPair, KdfParams } from "@/shared/lib/crypto";

type Phase = "input" | "recovering" | "password_set" | "success" | "error";

const TARGET_KDF_PARAMS: KdfParams = {
  algorithm: "argon2id",
  memory: 65536,
  iterations: 3,
  parallelism: 4,
  hash_length: 32,
};

const EMPTY_WORDS = (): string[] => Array(24).fill("");
const MAX_FILE_SIZE = 10 * 1024;

export default function RecoveryPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [phase, setPhase] = createSignal<Phase>("input");
  const [error, setError] = createSignal<string | null>(null);
  const [words, setWords] = createSignal<string[]>(EMPTY_WORDS());
  const [loading, setLoading] = createSignal(false);
  const [statusMessage, setStatusMessage] = createSignal("");

  const isPasswordReset = () => searchParams.password_reset === "true";
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");

  const [recoveredUmk, setRecoveredUmk] = createSignal<Uint8Array | null>(null);
  const [recoveredIdentityKeys, setRecoveredIdentityKeys] = createSignal<IdentityKeyPair | null>(null);

  let redirectTimer: ReturnType<typeof setTimeout> | null = null;
  let inputRefs: (HTMLInputElement | undefined)[] = [];
  let fileInputRef: HTMLInputElement | undefined;

  onCleanup(() => {
    if (redirectTimer !== null) clearTimeout(redirectTimer);
  });

  const handleWordChange = (index: number, value: string) => {
    // Paste 24 words into first field
    if (value.includes(" ") && index === 0) {
      const pasted = value.trim().toLowerCase().split(/\s+/);
      if (pasted.length === 24) {
        setWords(pasted);
        inputRefs[23]?.focus();
        return;
      }
    }

    const updated = [...words()];
    updated[index] = value.toLowerCase().trim();
    setWords(updated);

    if (value && index < 23) {
      inputRefs[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: KeyboardEvent) => {
    if (e.key === "ArrowRight" && index < 23) {
      inputRefs[index + 1]?.focus();
    } else if (e.key === "ArrowLeft" && index > 0) {
      inputRefs[index - 1]?.focus();
    } else if (e.key === "ArrowUp") {
      const target = index - 4;
      if (target >= 0) inputRefs[target]?.focus();
    } else if (e.key === "ArrowDown") {
      const target = index + 4;
      if (target < 24) inputRefs[target]?.focus();
    } else if (e.key === "Backspace" && !words()[index] && index > 0) {
      inputRefs[index - 1]?.focus();
    }
  };

  const handleFileUpload = async (e: Event) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    if (file.size > MAX_FILE_SIZE) {
      setError("File is too large. Recovery key files should be less than 10KB.");
      input.value = "";
      return;
    }

    try {
      const content = await file.text();
      const result = parseRecoveryKeyFile(content);

      if ("error" in result) {
        setError(result.error);
        setWords(EMPTY_WORDS());
      } else {
        const mnemonic = result.words.join(" ");
        if (!isValidMnemonic(mnemonic)) {
          setError("Invalid recovery key file: contains invalid BIP39 words.");
          setWords(EMPTY_WORDS());
        } else {
          setWords(result.words);
          setError(null);
        }
      }
    } catch {
      setError("Failed to read file.");
      setWords(EMPTY_WORDS());
    }

    input.value = "";
  };

  const handleClear = () => {
    setWords(EMPTY_WORDS());
    setError(null);
    setPhase("input");
  };

  const handleRecover = async (e: Event) => {
    e.preventDefault();
    const auth = authState();
    if (!auth) {
      navigate("/auth/login");
      return;
    }

    const mnemonic = words().join(" ");

    if (!isValidMnemonic(mnemonic)) {
      setError("Invalid recovery phrase. Please check all 24 words.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      setPhase("recovering");
      setStatusMessage("Fetching recovery data\u2026");
      const recovery = await authApi.getRecovery();

      setStatusMessage("Deriving recovery key\u2026");
      const ruk = await deriveRukFromMnemonic(mnemonic);

      setStatusMessage("Decrypting master key\u2026");
      let umk: Uint8Array;
      try {
        umk = unwrapUmkWithRuk(
          base64UrlDecode(recovery.recovery_encrypted_umk!),
          base64UrlDecode(recovery.recovery_nonce!),
          ruk,
          auth.user.id,
        );
      } catch {
        throw new Error("Invalid recovery phrase. The mnemonic does not match this account.");
      }

      setStatusMessage("Decrypting identity keys\u2026");
      const identityKeys = decryptIdentityPrivateKeys(
        {
          encryptedEcdhPrivate: base64UrlDecode(recovery.encrypted_ecdh_private!),
          ecdhPrivateNonce: base64UrlDecode(recovery.encrypted_ecdh_private_nonce!),
          encryptedSigningPrivate: base64UrlDecode(recovery.encrypted_signing_private!),
          signingPrivateNonce: base64UrlDecode(recovery.encrypted_signing_private_nonce!),
        },
        umk,
        auth.user.id,
      );

      setStatusMessage("Getting recovery challenge\u2026");
      const challengeRes = await authApi.recoveryChallenge(auth.user.email);
      const challenge = base64UrlDecode(challengeRes.challenge);

      setStatusMessage("Signing challenge\u2026");
      const timestampMs = Date.now();
      const emailBytes = new TextEncoder().encode(auth.user.email.toLowerCase());
      const timestampBytes = new Uint8Array(8);
      const view = new DataView(timestampBytes.buffer);
      view.setBigUint64(0, BigInt(timestampMs), true);

      const prefix = new TextEncoder().encode("recovery-session:");
      const message = new Uint8Array(
        prefix.length + challenge.length + emailBytes.length + timestampBytes.length,
      );
      message.set(prefix, 0);
      message.set(challenge, prefix.length);
      message.set(emailBytes, prefix.length + challenge.length);
      message.set(timestampBytes, prefix.length + challenge.length + emailBytes.length);

      const signature = sign(message, identityKeys.signingPrivate);

      setStatusMessage("Creating session\u2026");
      await authApi.recoverySession({
        email: auth.user.email,
        challenge: challengeRes.challenge,
        signature: base64UrlEncode(signature),
        timestamp: timestampMs,
      });

      if (isPasswordReset()) {
        setRecoveredUmk(umk);
        setRecoveredIdentityKeys(identityKeys);
        setPhase("password_set");
        setLoading(false);
        return;
      }

      const sessionPdk = restoreSessionPdk() ?? undefined;
      setStatusMessage("Setting up new device\u2026");
      await registerDevice(auth, umk, identityKeys, auth.sessionId, sessionPdk);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Recovery failed");
      setPhase("error");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordSet = async (e: Event) => {
    e.preventDefault();
    const auth = authState();
    if (!auth || !recoveredUmk() || !recoveredIdentityKeys()) {
      navigate("/auth/login");
      return;
    }

    if (newPassword() !== confirmPassword()) {
      setError("Passwords do not match");
      return;
    }

    if (newPassword().length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const umk = recoveredUmk()!;
      const identityKeys = recoveredIdentityKeys()!;

      const salt = randomBytes(16);
      const saltBase64 = base64UrlEncode(salt);
      const derived = await deriveAuthKeys(newPassword(), saltBase64, TARGET_KDF_PARAMS);

      const umkWrapped = wrapUmk(umk, derived.puk, auth.user.id);

      const res = await authApi.passwordSet({
        new_auth_key: derived.authKeyBase64,
        new_salt: saltBase64,
        new_encrypted_umk: base64UrlEncode(umkWrapped.encryptedUmk),
        new_umk_nonce: base64UrlEncode(umkWrapped.nonce),
      });

      persistSessionPdk(derived.pdk);

      setPhase("recovering");
      setStatusMessage("Setting up new device\u2026");
      await registerDevice(auth, umk, identityKeys, res.session_id, derived.pdk);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Password set failed");
      setPhase("error");
    } finally {
      setLoading(false);
    }
  };

  async function registerDevice(
    auth: NonNullable<ReturnType<typeof authState>>,
    umk: Uint8Array,
    identityKeys: IdentityKeyPair,
    sessionId: string,
    pdk?: Uint8Array,
  ) {
    setStatusMessage("Generating device keys\u2026");
    const deviceKeys = generateDeviceKeyPair();
    await persistDeviceKeysOnly(deviceKeys.ecdhPrivate, deviceKeys.signingPrivate, auth.user.id, pdk);

    const clientNonce = generateClientNonce();
    const deviceSignature = signDeviceRegistration(
      deviceKeys.signingPublic,
      deviceKeys.ecdhPublic,
      clientNonce,
      identityKeys.signingPrivate,
    );

    setStatusMessage("Registering device\u2026");
    const pendingRes = await devicesApi.createPending({
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_ecdh_public_key: base64UrlEncode(deviceKeys.ecdhPublic),
      device_signing_public_key: base64UrlEncode(deviceKeys.signingPublic),
      client_nonce: base64UrlEncode(clientNonce),
      identity_signing_public_key: base64UrlEncode(identityKeys.signingPublic),
    });

    const approveRes = await devicesApi.approveWithoutPop(pendingRes.device_id, {
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
        sessionId,
        umk,
        identityKeys,
        expiresAt: auth.expiresAt,
      },
      {
        deviceId,
        deviceEcdhPrivate: deviceKeys.ecdhPrivate,
        deviceSigningPrivate: deviceKeys.signingPrivate,
      },
    );

    setStatusMessage("Restoring workspace keys\u2026");
    try {
      await restoreWorkspaceKeks(
        auth.user.id,
        deviceId,
        umk,
        identityKeys,
        deviceKeys.ecdhPrivate,
        deviceKeys.ecdhPublic,
      );
    } catch {
      // KEK restoration is best-effort
    }

    setPhase("success");
    setStatusMessage("Recovery complete!");
    redirectTimer = setTimeout(() => navigate("/"), 1500);
  }

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-2xl">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <KeyRoundIcon class="size-6" />
            {isPasswordReset() ? "Reset Password" : "Account Recovery"}
          </CardTitle>
          <CardDescription>
            {isPasswordReset()
              ? "Enter your 24-word recovery phrase to verify your identity, then set a new password."
              : "Restore access to your account using your 24-word recovery phrase."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Switch>
            <Match when={phase() === "recovering"}>
              <div class="flex flex-col items-center gap-4 py-12">
                <Spinner class="size-6" />
                <p class="text-muted-foreground">{statusMessage()}</p>
              </div>
            </Match>

            <Match when={phase() === "success"}>
              <div class="flex flex-col items-center gap-4 py-12">
                <div class="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
                  <CheckCircleIcon class="size-6 text-green-600" />
                </div>
                <p class="text-lg font-medium">Recovery Successful!</p>
                <p class="text-muted-foreground">Redirecting to your workspace&hellip;</p>
              </div>
            </Match>

            <Match when={phase() === "password_set" || (phase() === "error" && isPasswordReset() && recoveredUmk() != null)}>
              <form onSubmit={handlePasswordSet} class="space-y-4">
                <Show when={error()}>
                  {(err) => (
                    <Alert variant="destructive">
                      <AlertTriangleIcon />
                      <AlertDescription>{err()}</AlertDescription>
                    </Alert>
                  )}
                </Show>
                <Field>
                  <FieldLabel for="new-password">New Password</FieldLabel>
                  <Input
                    id="new-password"
                    type="password"
                    value={newPassword()}
                    onInput={(e) => setNewPassword(e.currentTarget.value)}
                    required
                    disabled={loading()}
                    autocomplete="new-password"
                  />
                </Field>
                <Field>
                  <FieldLabel for="confirm-password">Confirm Password</FieldLabel>
                  <Input
                    id="confirm-password"
                    type="password"
                    value={confirmPassword()}
                    onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                    required
                    disabled={loading()}
                    autocomplete="new-password"
                  />
                </Field>
                <Button type="submit" class="w-full" disabled={loading()}>
                  {loading() ? (
                    <span class="flex items-center gap-2">
                      <Spinner class="size-3" /> Setting password...
                    </span>
                  ) : (
                    "Set New Password"
                  )}
                </Button>
              </form>
            </Match>

            <Match when={phase() === "input" || (phase() === "error" && !(isPasswordReset() && recoveredUmk()))}>
              <form onSubmit={handleRecover} class="space-y-6">
                <Show when={error()}>
                  {(err) => (
                    <Alert variant="destructive">
                      <AlertTriangleIcon />
                      <AlertDescription>{err()}</AlertDescription>
                    </Alert>
                  )}
                </Show>

                <div class="space-y-2">
                  <div class="flex items-center justify-between">
                    <FieldLabel>Recovery Phrase</FieldLabel>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => fileInputRef?.click()}
                    >
                      <UploadIcon class="size-3 mr-1" />
                      Upload File
                    </Button>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".txt"
                      onChange={handleFileUpload}
                      class="hidden"
                    />
                  </div>
                  <p class="text-xs text-muted-foreground mb-4">
                    Upload your recovery key file or enter each word manually. You can also paste the full 24-word phrase into the first field.
                  </p>

                  <div class="grid grid-cols-4 gap-2">
                    <For each={words()}>
                      {(word, index) => (
                        <div class="flex items-center gap-1">
                          <span class="text-xs text-muted-foreground w-5 text-right">
                            {index() + 1}.
                          </span>
                          <Input
                            ref={(el) => { inputRefs[index()] = el; }}
                            type="text"
                            value={word}
                            onInput={(e) => handleWordChange(index(), e.currentTarget.value)}
                            onKeyDown={(e) => handleKeyDown(index(), e)}
                            placeholder="word"
                            class="h-8 text-sm font-mono"
                            autocomplete="off"
                            autocorrect="off"
                            autocapitalize="off"
                            spellcheck={false}
                            disabled={loading()}
                          />
                        </div>
                      )}
                    </For>
                  </div>
                </div>

                <div class="flex gap-2">
                  <Button type="submit" class="flex-1" disabled={loading()}>
                    {loading() ? (
                      <span class="flex items-center gap-2">
                        <Spinner class="size-3" /> Recovering...
                      </span>
                    ) : (
                      isPasswordReset() ? "Verify Recovery Phrase" : "Recover Account"
                    )}
                  </Button>
                  <Show when={phase() === "error"}>
                    <Button type="button" variant="outline" onClick={() => { setPhase("input"); setError(null); }}>
                      Try Again
                    </Button>
                  </Show>
                  <Show when={phase() === "input"}>
                    <Button type="button" variant="outline" onClick={handleClear}>
                      Clear
                    </Button>
                  </Show>
                </div>

                <div class="text-center">
                  <a
                    href="/auth/login"
                    class="text-sm text-muted-foreground hover:text-primary underline"
                  >
                    Back to Login
                  </a>
                </div>
              </form>

              <div class="mt-6 p-4 bg-muted rounded-lg">
                <h4 class="font-semibold text-sm mb-2">Important Security Notes</h4>
                <ul class="text-xs text-muted-foreground space-y-1">
                  <li>Never share your recovery phrase with anyone</li>
                  <li>RefMD staff will never ask for your recovery phrase</li>
                  <li>Make sure you're on the official RefMD website</li>
                  <li>Your recovery phrase proves you own the account</li>
                </ul>
              </div>
            </Match>
          </Switch>
        </CardContent>
      </Card>
    </main>
  );
}

function getDeviceName(): string {
  const ua = navigator.userAgent;
  if (/Chrome/.test(ua)) return "Chrome (Recovery)";
  if (/Firefox/.test(ua)) return "Firefox (Recovery)";
  if (/Safari/.test(ua)) return "Safari (Recovery)";
  return "Browser (Recovery)";
}

function getDeviceType(): string {
  if (/Mobi|Android/i.test(navigator.userAgent)) return "mobile";
  return "desktop";
}

async function restoreWorkspaceKeks(
  userId: string,
  deviceId: string,
  umk: Uint8Array,
  identityKeys: IdentityKeyPair,
  deviceEcdhPrivate: Uint8Array,
  deviceEcdhPublic: Uint8Array,
): Promise<void> {
  const { workspace_ids } = await encryptionApi.getWorkspaceIds();

  for (const workspaceId of workspace_ids) {
    try {
      await restoreKekForWorkspace(
        workspaceId,
        userId,
        deviceId,
        umk,
        identityKeys,
        deviceEcdhPrivate,
        deviceEcdhPublic,
      );
    } catch {
      // Per-workspace best-effort
    }
  }
}

async function restoreKekForWorkspace(
  workspaceId: string,
  userId: string,
  deviceId: string,
  umk: Uint8Array,
  identityKeys: IdentityKeyPair,
  deviceEcdhPrivate: Uint8Array,
  deviceEcdhPublic: Uint8Array,
): Promise<void> {
  const existing = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId);
  if (existing.keys.length > 0) return;
  const currentKekVersion = existing.current_kek_version;

  const memberEnvelope = await encryptionApi.getMemberEnvelopeWithPop(workspaceId);
  if (memberEnvelope && memberEnvelope.sender_ecdh_public_key && memberEnvelope.sender_signing_public_key) {
    const senderEcdhPk = base64UrlDecode(memberEnvelope.sender_ecdh_public_key);
    const senderSigningPk = base64UrlDecode(memberEnvelope.sender_signing_public_key);

    const tofuResult = await verifyTofu(userId, memberEnvelope.sender_device_id, senderSigningPk, senderEcdhPk);
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

    return;
  }

  let backupData: { encrypted_kek: string; nonce: string; key_version: number } | null = null;
  try {
    backupData = await encryptionApi.getKekBackupWithPop(workspaceId);
  } catch {
    // No backup available
  }

  if (backupData) {
    const kek = unwrapKekFromBackup(
      base64UrlDecode(backupData.encrypted_kek),
      base64UrlDecode(backupData.nonce),
      umk,
      workspaceId,
      userId,
      backupData.key_version,
    );

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

    return;
  }

  if (currentKekVersion > 0) return;

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
  } catch {
    // 409 Conflict: KEK already exists
  }
}
