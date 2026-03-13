import { Show, createEffect, createSignal, type ParentProps } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import { Sidebar } from "@/widgets/sidebar";
import { SettingsDialog } from "@/widgets/settings";
import {
  currentWorkspaceId,
  setCurrentWorkspaceId,
  useWorkspaces,
} from "@/entities/workspace";
import { workspacesApi, encryptionApi } from "@/shared/api";
import { authState, deviceState } from "@/shared/lib/auth-state";
import {
  generateKek,
  encryptKekForDevice,
  wrapKekWithUmk,
  base64UrlEncode,
} from "@/shared/lib/crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import { usePendingDevices, performKekRotation } from "@/features/devices";
import { Button } from "@/shared/ui/button";
import { BellIcon } from "lucide-solid";

const rotationAttempted = new Set<string>();

export function AppShell(props: ParentProps) {
  const queryClient = useQueryClient();
  const [settingsOpen, setSettingsOpen] = createSignal(false);

  const { workspaces, workspacesNeedingRotation } = useWorkspaces();

  createEffect(() => {
    const pending = workspacesNeedingRotation();
    if (pending.length === 0) return;

    const auth = authState();
    const device = deviceState();
    if (!auth?.umk || !auth.identityKeys || !device?.deviceEcdhPrivate) return;

    const initiatorWorkspaces = pending.filter(
      (ws) =>
        ws.kek_rotation_initiator_user_id === auth.user.id &&
        !rotationAttempted.has(ws.workspace_id),
    );
    if (initiatorWorkspaces.length === 0) return;

    for (const ws of initiatorWorkspaces) {
      rotationAttempted.add(ws.workspace_id);
    }

    performKekRotation(initiatorWorkspaces, {
      user: auth.user,
      umk: auth.umk,
      identityKeys: auth.identityKeys,
    }, {
      deviceId: device.deviceId,
      deviceEcdhPrivate: device.deviceEcdhPrivate,
    })
      .then(() => {
        for (const ws of initiatorWorkspaces) {
          rotationAttempted.delete(ws.workspace_id);
        }
        queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      })
      .catch(() => {
        for (const ws of initiatorWorkspaces) {
          rotationAttempted.delete(ws.workspace_id);
        }
      });
  });

  const handleSelectWorkspace = (id: string) => {
    setCurrentWorkspaceId(id);
  };

  const handleCreateWorkspace = async (data: { name: string; description?: string; icon?: string }) => {
    const result = await workspacesApi.create(data);
    if (!result.id) return;

    const auth = authState();
    const device = deviceState();

    if (auth?.umk && auth.user && device?.deviceId && device.deviceEcdhPrivate) {
      const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
      const kek = generateKek();

      const kekWrapped = encryptKekForDevice(
        kek,
        device.deviceEcdhPrivate,
        deviceEcdhPublic,
        result.id,
        auth.user.id,
        device.deviceId,
        device.deviceId,
        1,
      );

      await encryptionApi.createWorkspaceKeyWithPop(result.id, {
        device_id: device.deviceId,
        key_version: 1,
        sender_device_id: device.deviceId,
        encrypted_kek: base64UrlEncode(kekWrapped.ciphertext),
        nonce: base64UrlEncode(kekWrapped.nonce),
        is_active: true,
      });

      const kekBackup = wrapKekWithUmk(kek, auth.umk, result.id, auth.user.id, 1);

      await encryptionApi.createKekBackupWithPop(result.id, {
        key_version: 1,
        encrypted_kek: base64UrlEncode(kekBackup.encryptedKek),
        nonce: base64UrlEncode(kekBackup.nonce),
      });
    }

    queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    setCurrentWorkspaceId(result.id);
  };

  const { pendingCount } = usePendingDevices();

  const notificationSlot = () => (
    <Show when={pendingCount() > 0}>
      <Button
        variant="ghost"
        size="icon"
        class="size-9 relative"
        onClick={() => setSettingsOpen(true)}
        aria-label="Pending device approvals"
      >
        <BellIcon class="size-4" />
        <span class="absolute -top-0.5 -right-0.5 size-4 rounded-full bg-destructive text-destructive-foreground text-[10px] flex items-center justify-center">
          {pendingCount()}
        </span>
      </Button>
    </Show>
  );

  return (
    <div class="flex h-screen">
      <Sidebar
        workspaces={workspaces()}
        currentWorkspaceId={currentWorkspaceId()}
        onSelectWorkspace={handleSelectWorkspace}
        onCreateWorkspace={handleCreateWorkspace}
        notificationSlot={notificationSlot()}
        onSettingsClick={() => setSettingsOpen(true)}
      />
      <div class="flex-1 overflow-hidden">{props.children}</div>
      <SettingsDialog open={settingsOpen()} onOpenChange={setSettingsOpen} />
    </div>
  );
}
