import { createSignal } from "solid-js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { RadioGroup, RadioGroupItem } from "@/shared/ui/radio-group";
import { Spinner } from "@/shared/ui/spinner";
import { devicesApi, encryptionApi } from "@/shared/api";
import type { DeviceInfo, WorkspaceRotationInfo } from "@/shared/api/devices";
import { authState, deviceState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import { base64UrlEncode, base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface Props {
  device: DeviceInfo;
  onClose: () => void;
  onRevoked: () => void;
  onError: (msg: string) => void;
}

export function RevokeDeviceDialog(props: Props) {
  const [mode, setMode] = createSignal<"security" | "retire">("security");
  const [loading, setLoading] = createSignal(false);

  const handleRevoke = async () => {
    setLoading(true);
    try {
      const authSnapshot = authState();
      const deviceSnapshot = deviceState();
      if (!cryptoWorkerReady() || !authSnapshot || !deviceSnapshot?.deviceId) {
        props.onError("Identity keys or device not available");
        return;
      }

      const worker = getCryptoWorker();
      const revokedAtMs = Date.now();

      const { signature } = await worker.signMessage({
        action: "device_revocation",
        payload: {
          device_id: props.device.id,
          revocation_mode: mode(),
          revoked_at: revokedAtMs,
          revoked_by_device_id: deviceSnapshot.deviceId,
          user_id: authSnapshot.user.id,
        },
      });

      const result = await devicesApi.revoke(
        props.device.id,
        mode(),
        base64UrlEncode(signature),
        revokedAtMs,
      );

      if (mode() === "security" && result.workspaces_needing_kek_rotation.length > 0) {
        try {
          await performKekRotation(
            result.workspaces_needing_kek_rotation,
            authSnapshot.user.id,
            deviceSnapshot.deviceId,
          );
        } catch (rotationErr) {
          props.onRevoked();
          props.onError(
            `Device removed, but key rotation failed: ${rotationErr instanceof Error ? rotationErr.message : "unknown error"}. Keys will be rotated on next access.`,
          );
          return;
        }
      }

      props.onRevoked();
    } catch (err) {
      if (err instanceof Error && err.message.includes("retire_blocked_by_unbound_sessions")) {
        props.onError(
          "Cannot use safe removal while a device registration or recovery is in progress. Please complete or cancel it first, or use the 'Lost or compromised' option.",
        );
      } else {
        props.onError(err instanceof Error ? err.message : "Revocation failed");
      }
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
          <DialogTitle>Remove Device</DialogTitle>
          <DialogDescription>Removing "{props.device.name}". Choose the reason:</DialogDescription>
        </DialogHeader>

        <RadioGroup value={mode()} onChange={(v: string) => setMode(v as "security" | "retire")}>
          <div class="space-y-3">
            <label class="flex items-start gap-3 p-3 rounded-lg border cursor-pointer hover:bg-accent/50 transition-colors">
              <RadioGroupItem value="security" />
              <div>
                <span class="font-medium">Lost or compromised</span>
                <p class="text-sm text-muted-foreground mt-1">
                  This device was lost, stolen, or may have been accessed by someone else. All
                  workspace keys will be regenerated.
                </p>
              </div>
            </label>

            <label class="flex items-start gap-3 p-3 rounded-lg border cursor-pointer hover:bg-accent/50 transition-colors">
              <RadioGroupItem value="retire" />
              <div>
                <span class="font-medium">Safely retiring</span>
                <p class="text-sm text-muted-foreground mt-1">
                  This device is in your possession and will be wiped or factory-reset. No key
                  regeneration needed.
                </p>
              </div>
            </label>
          </div>
        </RadioGroup>

        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={loading()}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleRevoke} disabled={loading()}>
            {loading() ? (
              <span class="flex items-center gap-2">
                <Spinner class="size-3" />
                {mode() === "security" ? "Regenerating keys..." : "Removing..."}
              </span>
            ) : (
              "Remove Device"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export async function performKekRotation(
  workspaces: WorkspaceRotationInfo[],
  userId: string,
  currentDeviceId: string,
): Promise<void> {
  const worker = getCryptoWorker();
  const activeDevices = await devicesApi.list();

  // TOFU + identity_signature re-verification before key distribution
  for (const d of activeDevices.devices) {
    const signingPk = base64UrlDecode(d.signing_public_key);
    const ecdhPk = base64UrlDecode(d.ecdh_public_key);
    const tofuResult = await worker.tofuVerify({
      userId,
      deviceId: d.id,
      signingPublicKey: signingPk,
      ecdhPublicKey: ecdhPk,
    });
    if (tofuResult.status === "ecdh_key_mismatch" || tofuResult.status === "identity_key_changed") {
      throw new Error("Device key verification failed. Aborting KEK rotation.");
    }

    if (!d.identity_signature || !d.client_nonce) {
      throw new Error(`Device ${d.name}: Missing identity signature. Aborting KEK rotation.`);
    }
    const sig = base64UrlDecode(d.identity_signature);
    const nonce = base64UrlDecode(d.client_nonce!);
    const identitySigningPublic = authState()?.identitySigningPublic;
    if (!identitySigningPublic) {
      throw new Error("Identity signing public key not available. Aborting KEK rotation.");
    }
    const sigValid = await worker.verifyDeviceIdentitySignature({
      deviceId: d.id,
      deviceSigningPublic: signingPk,
      deviceEcdhPublic: ecdhPk,
      clientNonce: nonce,
      identitySignature: sig,
      identitySigningPublic,
    });
    if (!sigValid) {
      throw new Error(`Device ${d.name}: Invalid identity signature. Aborting KEK rotation.`);
    }

    if (tofuResult.status === "first_seen") {
      await worker.tofuTrustDevice({
        userId,
        deviceId: d.id,
        signingPublicKey: signingPk,
        ecdhPublicKey: ecdhPk,
      });
    } else if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({ userId, deviceId: d.id });
    }
  }

  const failedWorkspaces: string[] = [];

  for (const ws of workspaces) {
    const workspaceId = ws.workspace_id;
    try {
      const newVersion = ws.current_kek_version + 1;

      // Generate new KEK inside the worker
      await worker.generateKek(workspaceId, newVersion);

      // Step 1: Device envelopes for all active devices
      for (const d of activeDevices.devices) {
        const targetEcdhPublic = base64UrlDecode(d.ecdh_public_key);
        const envelope = await worker.encryptKekForDevice({
          workspaceId,
          userId,
          senderDeviceId: currentDeviceId,
          targetDeviceId: d.id,
          targetDeviceEcdhPublic: targetEcdhPublic,
          keyVersion: newVersion,
        });

        await encryptionApi.createWorkspaceKeyWithPop(workspaceId, {
          device_id: d.id,
          key_version: newVersion,
          sender_device_id: currentDeviceId,
          encrypted_kek: base64UrlEncode(envelope.encrypted),
          nonce: base64UrlEncode(envelope.nonce),
          is_active: true,
        });
      }

      // Step 2: Member envelopes for all workspace members
      const { members } = await encryptionApi.getWorkspaceMemberKeys(workspaceId);
      const envelopes = await Promise.all(
        members.map(async (member) => {
          const targetEcdhPublic = base64UrlDecode(member.ecdh_public_key);
          const envelope = await worker.encryptKekForMember({
            workspaceId,
            targetUserId: member.user_id,
            targetIdentityEcdhPublic: targetEcdhPublic,
            senderDeviceId: currentDeviceId,
            keyVersion: newVersion,
          });
          return {
            target_user_id: member.user_id,
            key_version: newVersion,
            sender_device_id: currentDeviceId,
            encrypted_kek: base64UrlEncode(envelope.encrypted),
            nonce: base64UrlEncode(envelope.nonce),
          };
        }),
      );

      await encryptionApi.saveMemberEnvelopes(workspaceId, envelopes);

      // Step 3: UMK backup with new KEK
      const kekBackup = await worker.wrapKekWithUmk({
        workspaceId,
        userId,
        keyVersion: newVersion,
      });

      await encryptionApi.createKekBackupWithPop(workspaceId, {
        key_version: newVersion,
        encrypted_kek: base64UrlEncode(kekBackup.encrypted),
        nonce: base64UrlEncode(kekBackup.nonce),
      });

      // Step 4: Complete rotation
      await encryptionApi.completeKekRotation(workspaceId, newVersion);
    } catch {
      failedWorkspaces.push(workspaceId);
    }
  }

  if (failedWorkspaces.length > 0) {
    throw new Error(
      `KEK rotation failed for ${failedWorkspaces.length} workspace(s). Keys will be rotated on next access.`,
    );
  }
}
