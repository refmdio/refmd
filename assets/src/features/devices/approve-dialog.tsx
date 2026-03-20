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
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import { authState, deviceState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import { base64UrlEncode, base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface Props {
  device: DeviceRegistrationInfo;
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
    return auth?.identitySigningPublic ?? null;
  };

  // TOFU check: verify pending device keys before SAS display
  const checkInitialTofu = async () => {
    const auth = authState();
    if (!auth) {
      setTofuChecked(true);
      return;
    }

    const worker = getCryptoWorker();
    const signingPk = base64UrlDecode(props.device.signing_public_key);
    const ecdhPk = base64UrlDecode(props.device.ecdh_public_key);

    const result = await worker.tofuVerify({
      userId: auth.user.id,
      deviceId: props.device.id,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
    });

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
      if (!cryptoWorkerReady() || !auth || !device?.deviceId) {
        props.onError("Identity keys or device not available");
        return;
      }

      const worker = getCryptoWorker();

      // Step 1: Approve with identity signature
      const targetSigningPublic = base64UrlDecode(props.device.signing_public_key);
      const targetEcdhPublic = base64UrlDecode(props.device.ecdh_public_key);
      const targetClientNonce = base64UrlDecode(props.device.client_nonce);

      const { signature } = await worker.signDeviceApproval({
        deviceId: props.device.id,
        deviceSigningPublic: targetSigningPublic,
        deviceEcdhPublic: targetEcdhPublic,
        clientNonce: targetClientNonce,
      });

      const approveRes = await devicesApi.approve(props.device.id, {
        identity_signature: base64UrlEncode(signature),
      });

      const newDeviceId = approveRes.device.id;

      // Anchor SAS-verified keys: compare fresh server keys against SAS-verified keys
      // to detect server-side key substitution between SAS display and post-approval fetch
      const { devices: freshDevices } = await devicesApi.list();
      const freshTarget = freshDevices.find((d) => d.id === newDeviceId);
      if (!freshTarget) {
        props.onError("Approved device not found on server");
        return;
      }
      if (
        freshTarget.signing_public_key !== props.device.signing_public_key ||
        freshTarget.ecdh_public_key !== props.device.ecdh_public_key
      ) {
        props.onError(
          "Server returned different keys after approval. Possible key substitution. Aborting.",
        );
        return;
      }
      const verifiedEcdhPublic = base64UrlDecode(freshTarget.ecdh_public_key);
      const verifiedSigningPublic = base64UrlDecode(freshTarget.signing_public_key);

      // Verify identity_signature on freshly fetched device
      if (!freshTarget.identity_signature || !freshTarget.client_nonce) {
        props.onError("Approved device missing identity signature. Aborting.");
        return;
      }
      const freshSig = base64UrlDecode(freshTarget.identity_signature);
      const freshNonce = base64UrlDecode(freshTarget.client_nonce!);
      const sigValid = await worker.verifyDeviceIdentitySignature({
        deviceId: newDeviceId,
        deviceSigningPublic: verifiedSigningPublic,
        deviceEcdhPublic: verifiedEcdhPublic,
        clientNonce: freshNonce,
        identitySignature: freshSig,
        identitySigningPublic: auth.identitySigningPublic!,
      });
      if (!sigValid) {
        props.onError(
          "Identity signature verification failed. Possible server-side tampering. Aborting.",
        );
        return;
      }

      // TOFU: persist trust for SAS-verified + server-confirmed keys
      const tofuResult = await worker.tofuVerify({
        userId: auth.user.id,
        deviceId: newDeviceId,
        signingPublicKey: verifiedSigningPublic,
        ecdhPublicKey: verifiedEcdhPublic,
      });
      if (
        tofuResult.status === "ecdh_key_mismatch" ||
        tofuResult.status === "identity_key_changed"
      ) {
        props.onError("Key verification failed before key distribution. Aborting.");
        return;
      }
      if (tofuResult.status === "first_seen") {
        await worker.tofuTrustDevice({
          userId: auth.user.id,
          deviceId: newDeviceId,
          signingPublicKey: verifiedSigningPublic,
          ecdhPublicKey: verifiedEcdhPublic,
        });
      } else if (tofuResult.status === "known_trusted") {
        await worker.tofuUpdateLastSeen({ userId: auth.user.id, deviceId: newDeviceId });
      }

      setStep("distributing");

      // Step 2: Trust state transfer (before KEK/UMK, best-effort)
      try {
        await transferTrustState(newDeviceId, verifiedEcdhPublic, props.transferNonce);
      } catch {
        // Trust state transfer is best-effort
      }

      // Step 3: Distribute KEK for each workspace (before UMK)
      try {
        await distributeKeks(device.deviceId, newDeviceId, verifiedEcdhPublic, auth.user.id);
      } catch {
        // KEK distribution is best-effort
      }

      // Step 4: Distribute UMK (triggers pending_approved SSE)
      const encrypted = await worker.ecdhEncryptUmkForDevice({
        theirPublic: verifiedEcdhPublic,
        senderDeviceId: device.deviceId,
        targetDeviceId: newDeviceId,
      });

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
    <Dialog
      open
      onOpenChange={(open: boolean) => {
        if (!open) props.onClose();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Approve New Device</DialogTitle>
          <DialogDescription>
            "{props.device.name}" ({props.device.device_type}) is requesting access. Verify that the
            emojis below match the ones shown on the new device.
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
                await devicesApi.rejectRegistration(props.device.id);
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
  targetDeviceId: string,
  targetEcdhPublic: Uint8Array,
  userId: string,
): Promise<void> {
  const worker = getCryptoWorker();
  const { workspace_ids } = await encryptionApi.getWorkspaceIds();

  for (const workspaceId of workspace_ids) {
    try {
      const { keys, current_kek_version } = await encryptionApi.getWorkspaceKeysWithPop(
        workspaceId,
        senderDeviceId,
      );
      if (keys.length === 0 || current_kek_version === 0) continue;

      const activeKey = keys.find((k) => k.key_version === current_kek_version);
      if (!activeKey?.sender_ecdh_public_key || !activeKey.sender_signing_public_key) continue;

      const senderSigningPk = base64UrlDecode(activeKey.sender_signing_public_key);
      const senderEcdhPk = base64UrlDecode(activeKey.sender_ecdh_public_key);

      const tofuResult = await worker.tofuVerify({
        userId,
        deviceId: activeKey.sender_device_id,
        signingPublicKey: senderSigningPk,
        ecdhPublicKey: senderEcdhPk,
      });
      if (
        tofuResult.status === "identity_key_changed" ||
        tofuResult.status === "ecdh_key_mismatch"
      ) {
        throw new Error("Key verification failed for KEK sender device. Aborting distribution.");
      }
      if (tofuResult.status === "first_seen") {
        await worker.tofuTrustDevice({
          userId,
          deviceId: activeKey.sender_device_id,
          signingPublicKey: senderSigningPk,
          ecdhPublicKey: senderEcdhPk,
        });
      } else if (tofuResult.status === "known_trusted") {
        await worker.tofuUpdateLastSeen({
          userId,
          deviceId: activeKey.sender_device_id,
        });
      }

      await worker.decryptKekFromDeviceEnvelope({
        encryptedKek: base64UrlDecode(activeKey.encrypted_kek),
        nonce: base64UrlDecode(activeKey.nonce),
        senderEcdhPublic: senderEcdhPk,
        workspaceId,
        userId,
        senderDeviceId: activeKey.sender_device_id,
        targetDeviceId: senderDeviceId,
        keyVersion: activeKey.key_version,
      });

      const encrypted = await worker.encryptKekForDevice({
        workspaceId,
        userId,
        senderDeviceId,
        targetDeviceId,
        targetDeviceEcdhPublic: targetEcdhPublic,
        keyVersion: activeKey.key_version,
      });

      await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
        device_id: targetDeviceId,
        sender_device_id: senderDeviceId,
        encrypted_kek: base64UrlEncode(encrypted.encrypted),
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
  targetDeviceId: string,
  targetEcdhPublic: Uint8Array,
  preReceivedNonce: string | null,
): Promise<void> {
  // Use pre-captured nonce from SSE, fall back to waiting
  const nonceBase64 = preReceivedNonce ?? (await waitForTrustTransferNonce(targetDeviceId));
  if (!nonceBase64) return;

  const worker = getCryptoWorker();
  const transferNonce = base64UrlDecode(nonceBase64);

  const encrypted = await worker.encryptTrustState({
    targetDeviceId,
    targetDeviceEcdhPublic: targetEcdhPublic,
    transferNonce,
  });

  if ("empty" in encrypted) return;

  await trustTransferApi.submitState({
    target_device_id: targetDeviceId,
    transfer_nonce: nonceBase64,
    ciphertext: base64UrlEncode(encrypted.ciphertext),
    nonce: base64UrlEncode(encrypted.nonce),
    signature: base64UrlEncode(encrypted.signature),
  });
}

function waitForTrustTransferNonce(targetDeviceId: string): Promise<string | null> {
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
