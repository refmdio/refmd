import {
  createContext,
  createEffect,
  createSignal,
  onCleanup,
  useContext,
  type Accessor,
} from "solid-js";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import { devicesApi } from "@/shared/api";
import { authState, deviceState } from "@/entities/session";
import {
  DeviceEventsJoinError,
  joinUserDeviceEvents,
} from "@/features/devices/lib/device-events-channel";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";

interface KekRotationNeeded {
  workspace_id: string;
  current_kek_version: number;
}

interface PendingDeviceContextValue {
  pendingDevices: Accessor<DeviceRegistrationInfo[]>;
  pendingCount: Accessor<number>;
  transferNonces: Accessor<Record<string, string>>;
  kekRotationsNeeded: Accessor<KekRotationNeeded[]>;
  showApprovalDialog: (device: DeviceRegistrationInfo) => void;
  refetchPending: () => Promise<void>;
}

interface PendingDeviceMonitorState {
  contextValue: PendingDeviceContextValue;
  currentDialog: Accessor<DeviceRegistrationInfo | null>;
  approvalError: Accessor<string | null>;
  handleDialogClose: () => void;
  handleApproved: () => void;
  handleApprovalError: (message: string) => void;
}

export const PendingDeviceContext = createContext<PendingDeviceContextValue>();

export function usePendingDevices(): PendingDeviceContextValue {
  const ctx = useContext(PendingDeviceContext);
  if (!ctx) {
    throw new Error("usePendingDevices must be used within PendingDeviceMonitor");
  }
  return ctx;
}

export function usePendingDeviceMonitorState(): PendingDeviceMonitorState {
  const [pendingDevices, setPendingDevices] = createSignal<DeviceRegistrationInfo[]>([]);
  const [currentDialog, setCurrentDialog] = createSignal<DeviceRegistrationInfo | null>(null);
  const [approvalError, setApprovalError] = createSignal<string | null>(null);
  const [transferNonces, setTransferNonces] = createSignal<Record<string, string>>({});
  const [kekRotationsNeeded, setKekRotationsNeeded] = createSignal<KekRotationNeeded[]>([]);
  const dismissed = new Set<string>();
  const seen = new Set<string>();

  let deviceEvents: { dispose: () => void } | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let expiryTimers: ReturnType<typeof setTimeout>[] = [];
  let connectionGeneration = 0;

  const pendingCount = () => pendingDevices().length;

  const refetchPending = async () => {
    try {
      const res = await devicesApi.listRegistrations();
      setPendingDevices(res.devices);
      setKekRotationsNeeded([]);
    } catch {
      // Silently ignore. Device events will keep state updated.
    }
  };

  const showApprovalDialog = (device: DeviceRegistrationInfo) => {
    setApprovalError(null);
    setCurrentDialog(device);
  };

  const clearConnectionState = () => {
    connectionGeneration += 1;
    const activeEvents = deviceEvents;
    deviceEvents = undefined;
    activeEvents?.dispose();
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = undefined;
    }
  };

  const scheduleReconnect = (generation: number) => {
    if (generation !== connectionGeneration) return;

    if (!retryTimer) {
      const delay = Math.max(5000, getAuthTransportBackoffMs());
      retryTimer = setTimeout(() => {
        retryTimer = undefined;
        if (generation === connectionGeneration) {
          connectDeviceEvents();
        }
      }, delay);
    }
  };

  const connectDeviceEvents = () => {
    clearConnectionState();
    const generation = connectionGeneration;

    joinUserDeviceEvents({
      onPendingDeviceCreated: () => {
        void refetchPending();
      },
      onPendingDeviceRemoved: () => {
        void refetchPending();
      },
      onKekRotationNeeded: (data) => {
        if (data.workspace_id) {
          setKekRotationsNeeded((prev) => {
            if (prev.some((rotation) => rotation.workspace_id === data.workspace_id)) {
              return prev;
            }
            return [
              ...prev,
              {
                workspace_id: data.workspace_id!,
                current_kek_version: data.current_kek_version ?? 0,
              },
            ];
          });
        }
      },
      onTrustTransferNonceReady: (data) => {
        if (data.new_device_id && data.nonce) {
          setTransferNonces((prev) => ({
            ...prev,
            [data.new_device_id!]: data.nonce!,
          }));
        }
      },
      onClose: () => scheduleReconnect(generation),
      onError: () => scheduleReconnect(generation),
    })
      .then((handle) => {
        if (generation !== connectionGeneration) {
          handle.dispose();
          return;
        }
        deviceEvents = handle;
      })
      .catch((error) => {
        if (error instanceof DeviceEventsJoinError && error.reason === "existing_device_required") {
          return;
        }
        scheduleReconnect(generation);
      });
  };

  createEffect(() => {
    const auth = authState();
    const device = deviceState();
    if (!auth || !device?.deviceId) {
      clearConnectionState();
      return;
    }

    void refetchPending();
    connectDeviceEvents();

    onCleanup(() => {
      clearConnectionState();
    });
  });

  createEffect(() => {
    const devices = pendingDevices();
    for (const timer of expiryTimers) {
      clearTimeout(timer);
    }
    expiryTimers = [];

    for (const device of devices) {
      const ms = new Date(device.expires_at).getTime() - Date.now();
      if (ms > 0) {
        expiryTimers.push(
          setTimeout(() => {
            void refetchPending();
          }, ms + 500),
        );
      }
    }
  });

  onCleanup(() => {
    clearConnectionState();
    for (const timer of expiryTimers) {
      clearTimeout(timer);
    }
  });

  createEffect(() => {
    const dialog = currentDialog();
    if (!dialog) return;

    const devices = pendingDevices();
    if (!devices.some((device) => device.id === dialog.id)) {
      setCurrentDialog(null);
    }
  });

  createEffect(() => {
    const devices = pendingDevices();
    if (devices.length === 0 || currentDialog()) return;

    const newDevice = devices.find((device) => !seen.has(device.id) && !dismissed.has(device.id));
    if (newDevice) {
      seen.add(newDevice.id);
      setCurrentDialog(newDevice);
    }
  });

  const handleDialogClose = () => {
    const dialog = currentDialog();
    if (dialog) {
      dismissed.add(dialog.id);
    }
    setCurrentDialog(null);
  };

  const handleApproved = () => {
    setCurrentDialog(null);
    setApprovalError(null);
    void refetchPending();
  };

  const handleApprovalError = (message: string) => {
    setCurrentDialog(null);
    setApprovalError(message);
  };

  return {
    contextValue: {
      pendingDevices,
      pendingCount,
      transferNonces,
      kekRotationsNeeded,
      showApprovalDialog,
      refetchPending,
    },
    currentDialog,
    approvalError,
    handleDialogClose,
    handleApproved,
    handleApprovalError,
  };
}
