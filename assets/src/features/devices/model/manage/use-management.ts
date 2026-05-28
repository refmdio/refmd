import { createEffect, createSignal, on } from "solid-js";
import { createMutation, createQuery, useQueryClient } from "@tanstack/solid-query";
import type { DeviceInfo } from "@/shared/api/devices";
import { deviceState } from "@/entities/session";
import {
  DEVICES_QUERY_KEY,
  listDevices,
  renameDevice as renameDeviceRequest,
} from "../../lib/manage/management";
import { usePendingDevices } from "../monitor/pending-monitor";
import { useDeviceTofuVerification } from "./use-tofu-verification";

export function useDeviceManagement() {
  const queryClient = useQueryClient();
  const devices = createQuery(() => ({
    queryKey: DEVICES_QUERY_KEY,
    queryFn: listDevices,
  }));
  const refetchDevices = () => queryClient.invalidateQueries({ queryKey: DEVICES_QUERY_KEY });
  const { pendingDevices, showApprovalDialog, kekRotationsNeeded, refetchPending } =
    usePendingDevices();
  const [revokeTarget, setRevokeTarget] = createSignal<DeviceInfo | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [editingId, setEditingId] = createSignal<string | null>(null);
  const [editName, setEditName] = createSignal("");

  const currentDeviceId = () => deviceState()?.deviceId;
  const { tofuHardFail, tofuWarnings } = useDeviceTofuVerification(() => devices.data?.devices);

  createEffect(
    on(
      () => pendingDevices().length,
      () => {
        void refetchDevices();
      },
      { defer: true },
    ),
  );

  const renameDeviceMutation = createMutation(() => ({
    mutationFn: ({ deviceId, name }: { deviceId: string; name: string }) =>
      renameDeviceRequest(deviceId, name),
    onSuccess: () => {
      setEditingId(null);
      void refetchDevices();
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : "Rename failed");
    },
  }));

  const startEditing = (device: DeviceInfo) => {
    setEditingId(device.id);
    setEditName(device.name);
  };

  const cancelEditing = () => {
    setEditingId(null);
  };

  const submitRename = async (deviceId: string) => {
    const name = editName().trim();
    if (!name) return;
    await renameDeviceMutation.mutateAsync({ deviceId, name });
  };

  const openRevokeDialog = (device: DeviceInfo) => {
    setRevokeTarget(device);
  };

  const closeRevokeDialog = () => {
    setRevokeTarget(null);
  };

  const handleRevoked = () => {
    setRevokeTarget(null);
    void refetchDevices();
  };

  return {
    currentDeviceId,
    devices,
    editName,
    editingId,
    error,
    handleRevoked,
    kekRotationsNeeded,
    openRevokeDialog,
    pendingDevices,
    refetchPending,
    refetchDevices,
    renameDeviceMutation,
    revokeTarget,
    setEditName,
    setError,
    showApprovalDialog,
    startEditing,
    submitRename,
    tofuHardFail,
    tofuWarnings,
    cancelEditing,
    closeRevokeDialog,
  };
}
