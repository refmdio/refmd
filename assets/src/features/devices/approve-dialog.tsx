import { createSignal, Show } from "solid-js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
import { SafetyNumber } from "./safety-number";
import { devicesApi, encryptionApi, trustTransferApi } from "@/shared/api";
import type { PendingDeviceInfo } from "@/shared/api/devices";
import { authState, deviceState } from "@/shared/lib/auth-state";
import {
  base64UrlEncode,
  base64UrlDecode,
  signDeviceApproval,
  ecdhEncrypt,
  encryptKekForDevice,
  decryptKekFromDeviceEnvelope,
  verifyTofu,
  trustDevice,
  handleTofuResult,
  encryptTrustState,
} from "@/shared/lib/crypto";
import { getAllTofuEntries } from "@/shared/lib/trust-store";
import { buildDeviceUmkDistributionAad } from "@/shared/lib/crypto/aad";

interface Props {
  device: PendingDeviceInfo;
  transferNonce: string | null;
  onClose: () => void;
  onApproved: () => void;
  onError: (msg: string) => void;
}

export function ApproveDeviceDialog(props: Props) {
  const [loading, setLoading] = createSignal(false);
  const [step, setStep] = createSignal<"verify" | "distributing">("verify");
  const [tofuBlocked, setTofuBlocked] = createSignal<string | null>(null);
  const [tofuChecked, setTofuChecked] = createSignal(false);

  const identitySigningPublic = () => {
    const auth = authState();
    return auth?.identityKeys?.signingPublic ?? null;
  };

  // TOFU check: verify pending device keys before SAS display (design step 4.5)
  const checkInitialTofu = async () => {
    const auth = authState();
    if (!auth) {
      setTofuChecked(true);
      return;
    }

    const signingPk = base64UrlDecode(props.device.signing_public_key);
    const ecdhPk = base64UrlDecode(props.device.ecdh_public_key);

    const result = await verifyTofu(auth.user.id, props.device.id, signingPk, ecdhPk);

    if (result.status === "identity_key_changed") {
      setTofuBlocked("Identity key changed for this device. This may indicate tampering.");
    } else if (result.status === "ecdh_key_mismatch") {
      setTofuBlocked("ECDH key mismatch for this device. This may indicate tampering.");
    }
    setTofuChecked(true);
  };

  // Run initial TOFU check (blocking: button disabled until complete)
  checkInitialTofu().catch(() => {
    setTofuBlocked("Key verification failed. Cannot verify device authenticity.");
    setTofuChecked(true);
  });

  const handleApprove = async () => {
    setLoading(true);
    try {
      const auth = authState();
      const device = deviceState();
      if (!auth?.identityKeys || !auth.umk || !device?.deviceId || !device.deviceEcdhPrivate || !device.deviceSigningPrivate) {
        props.onError("Identity keys or device not available");
        return;
      }

      // Step 1: Approve with identity signature
      const targetSigningPublic = base64UrlDecode(props.device.signing_public_key);
      const targetEcdhPublic = base64UrlDecode(props.device.ecdh_public_key);
      const targetClientNonce = base64UrlDecode(props.device.client_nonce);

      const signature = signDeviceApproval(
        targetSigningPublic,
        targetEcdhPublic,
        targetClientNonce,
        auth.identityKeys.signingPrivate,
      );

      const approveRes = await devicesApi.approve(props.device.id, {
        identity_signature: base64UrlEncode(signature),
      });

      const newDeviceId = approveRes.device.id;

      // TOFU: trust device after SAS verification + approval (design step 4.5)
      const signingPk = base64UrlDecode(props.device.signing_public_key);
      const ecdhPk = base64UrlDecode(props.device.ecdh_public_key);
      const tofuResult = await verifyTofu(auth.user.id, newDeviceId, signingPk, ecdhPk);
      if (tofuResult.status === "first_seen") {
        await trustDevice(tofuResult.newEntry);
      }

      // Step 9: TOFU re-verify with FRESH keys from server before distribution
      const { devices: freshDevices } = await devicesApi.list();
      const freshTarget = freshDevices.find(d => d.id === newDeviceId);
      if (!freshTarget) {
        props.onError("Approved device not found on server");
        return;
      }
      const verifiedEcdhPublic = base64UrlDecode(freshTarget.ecdh_public_key);
      const verifiedSigningPublic = base64UrlDecode(freshTarget.signing_public_key);
      const recheck = await verifyTofu(auth.user.id, newDeviceId, verifiedSigningPublic, verifiedEcdhPublic);
      if (recheck.status === "ecdh_key_mismatch" || recheck.status === "identity_key_changed") {
        props.onError("Key verification failed before key distribution. Aborting.");
        return;
      }

      setStep("distributing");

      // Step 2: Trust state transfer (before KEK/UMK per design, best-effort)
      try {
        await transferTrustState(
          auth.user.id,
          device.deviceId,
          device.deviceEcdhPrivate,
          device.deviceSigningPrivate,
          newDeviceId,
          verifiedEcdhPublic,
          props.transferNonce,
        );
      } catch {
        // Trust state transfer is best-effort per design
      }

      // Step 3: Distribute KEK for each workspace (before UMK per design)
      try {
        await distributeKeks(
          device.deviceId,
          device.deviceEcdhPrivate,
          newDeviceId,
          verifiedEcdhPublic,
          auth.user.id,
        );
      } catch {
        // KEK distribution is best-effort per design
      }

      // Step 4: Distribute UMK (triggers pending_approved SSE)
      const aad = buildDeviceUmkDistributionAad(
        auth.user.id,
        device.deviceId,
        newDeviceId,
      );
      const encrypted = ecdhEncrypt(
        auth.umk,
        device.deviceEcdhPrivate,
        verifiedEcdhPublic,
        "device_umk_wrap",
        aad,
      );

      await devicesApi.distributeUmk(
        newDeviceId,
        device.deviceId,
        base64UrlEncode(encrypted.ciphertext),
        base64UrlEncode(encrypted.nonce),
      );

      props.onApproved();
    } catch (err) {
      props.onError(err instanceof Error ? err.message : "Approval failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open: boolean) => { if (!open) props.onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Approve New Device</DialogTitle>
          <DialogDescription>
            "{props.device.name}" ({props.device.device_type}) is requesting access.
            Verify that the emojis below match the ones shown on the new device.
          </DialogDescription>
        </DialogHeader>

        <Show when={tofuBlocked()}>
          <Alert variant="destructive">
            <AlertDescription>{tofuBlocked()}</AlertDescription>
          </Alert>
        </Show>

        <Show when={!tofuChecked()}>
          <div class="flex items-center gap-2 py-4">
            <Spinner class="size-4" />
            <span class="text-sm text-muted-foreground">Verifying device keys...</span>
          </div>
        </Show>

        <Show when={tofuChecked() && !tofuBlocked() && identitySigningPublic()}>
          <SafetyNumber
            identitySigningPublic={identitySigningPublic()!}
            deviceSigningPublic={base64UrlDecode(props.device.signing_public_key)}
            deviceEcdhPublic={base64UrlDecode(props.device.ecdh_public_key)}
            clientNonce={base64UrlDecode(props.device.client_nonce)}
            class="py-4"
          />
        </Show>

        <Show when={step() === "distributing"}>
          <Alert>
            <AlertDescription class="flex items-center gap-2">
              <Spinner class="size-3" />
              Distributing encryption keys...
            </AlertDescription>
          </Alert>
        </Show>

        <DialogFooter>
          <Button
            variant="destructive"
            onClick={async () => {
              try {
                await devicesApi.rejectPending(props.device.id);
              } catch {
                // Already deleted or expired
              }
              props.onClose();
            }}
            disabled={loading()}
          >
            Reject
          </Button>
          <Button onClick={handleApprove} disabled={loading() || !tofuChecked() || !!tofuBlocked()}>
            {loading() ? (
              <span class="flex items-center gap-2">
                <Spinner class="size-3" />
                {step() === "verify" ? "Approving..." : "Distributing keys..."}
              </span>
            ) : (
              "Emojis Match - Approve"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

async function distributeKeks(
  senderDeviceId: string,
  senderEcdhPrivate: Uint8Array,
  targetDeviceId: string,
  targetEcdhPublic: Uint8Array,
  userId: string,
): Promise<void> {
  const { workspace_ids } = await encryptionApi.getWorkspaceIds();

  for (const workspaceId of workspace_ids) {
    try {
      const { keys, current_kek_version } = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, senderDeviceId);
      if (keys.length === 0 || current_kek_version === 0) continue;

      const activeKey = keys.find(k => k.key_version === current_kek_version);
      if (!activeKey?.sender_ecdh_public_key || !activeKey.sender_signing_public_key) continue;

      const senderSigningPk = base64UrlDecode(activeKey.sender_signing_public_key);
      const senderEcdhPk = base64UrlDecode(activeKey.sender_ecdh_public_key);

      const tofuResult = await verifyTofu(userId, activeKey.sender_device_id, senderSigningPk, senderEcdhPk);
      if (tofuResult.status === "identity_key_changed" || tofuResult.status === "ecdh_key_mismatch") {
        throw new Error("Key verification failed for KEK sender device. Aborting distribution.");
      }
      await handleTofuResult(tofuResult);

      const kek = decryptKekFromDeviceEnvelope(
        base64UrlDecode(activeKey.encrypted_kek),
        base64UrlDecode(activeKey.nonce),
        senderEcdhPrivate,
        senderEcdhPk,
        workspaceId,
        userId,
        activeKey.sender_device_id,
        senderDeviceId,
        activeKey.key_version,
      );

      const encrypted = encryptKekForDevice(
        kek,
        senderEcdhPrivate,
        targetEcdhPublic,
        workspaceId,
        userId,
        senderDeviceId,
        targetDeviceId,
        activeKey.key_version,
      );

      await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
        device_id: targetDeviceId,
        sender_device_id: senderDeviceId,
        encrypted_kek: base64UrlEncode(encrypted.ciphertext),
        nonce: base64UrlEncode(encrypted.nonce),
        key_version: activeKey.key_version,
        is_active: true,
      });
    } catch {
      // Per-workspace KEK distribution is best-effort
    }
  }
}

async function transferTrustState(
  userId: string,
  senderDeviceId: string,
  senderEcdhPrivate: Uint8Array,
  senderSigningPrivate: Uint8Array,
  targetDeviceId: string,
  targetEcdhPublic: Uint8Array,
  preReceivedNonce: string | null,
): Promise<void> {
  // Use pre-captured nonce from SSE, fall back to waiting
  const nonceBase64 = preReceivedNonce ?? (await waitForTrustTransferNonce(targetDeviceId));
  if (!nonceBase64) return;

  const tofuEntries = await getAllTofuEntries();
  if (tofuEntries.length === 0) return;

  const transferNonce = base64UrlDecode(nonceBase64);
  const snapshot = { tofuEntries, transferNonce };

  const encrypted = encryptTrustState(
    snapshot,
    senderEcdhPrivate,
    targetEcdhPublic,
    senderSigningPrivate,
    {
      userId,
      senderDeviceId,
      targetDeviceId,
    },
  );

  await trustTransferApi.submitState({
    target_device_id: targetDeviceId,
    transfer_nonce: nonceBase64,
    ciphertext: base64UrlEncode(encrypted.encryptedState),
    nonce: base64UrlEncode(encrypted.nonce),
    signature: base64UrlEncode(encrypted.signature),
  });
}

function waitForTrustTransferNonce(
  targetDeviceId: string,
): Promise<string | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      es.close();
      resolve(null);
    }, 10000);

    const es = new EventSource("/api/devices/events");
    es.addEventListener("trust_transfer_nonce_ready", (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.new_device_id === targetDeviceId) {
          clearTimeout(timeout);
          es.close();
          resolve(data.nonce as string);
        }
      } catch {
        // Parse error — continue waiting
      }
    });
    es.onerror = () => {
      clearTimeout(timeout);
      es.close();
      resolve(null);
    };
  });
}
