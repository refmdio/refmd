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
import { deviceState } from "@/entities/session";

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

  let eventSource: EventSource | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let expiryTimers: ReturnType<typeof setTimeout>[] = [];

  const pendingCount = () => pendingDevices().length;

  const refetchPending = async () => {
    try {
      const res = await devicesApi.listRegistrations();
      setPendingDevices(res.devices);
      setKekRotationsNeeded([]);
    } catch {
      // Silently ignore. SSE will keep state updated.
    }
  };

  const showApprovalDialog = (device: DeviceRegistrationInfo) => {
    setApprovalError(null);
    setCurrentDialog(device);
  };

  const clearConnectionState = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = undefined;
    }
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = undefined;
    }
  };

  const connectSse = () => {
    clearConnectionState();

    try {
      eventSource = new EventSource("/api/devices/events");

      eventSource.addEventListener("pending_device_created", () => {
        void refetchPending();
      });

      eventSource.addEventListener("pending_device_removed", () => {
        void refetchPending();
      });

      eventSource.addEventListener("kek_rotation_needed", (event) => {
        try {
          const data = JSON.parse((event as MessageEvent).data);
          if (data.workspace_id) {
            setKekRotationsNeeded((prev) => {
              if (prev.some((rotation) => rotation.workspace_id === data.workspace_id)) {
                return prev;
              }
              return [
                ...prev,
                {
                  workspace_id: data.workspace_id,
                  current_kek_version: data.current_kek_version,
                },
              ];
            });
          }
        } catch {
          // Parse error.
        }
      });

      eventSource.addEventListener("trust_transfer_nonce_ready", (event) => {
        try {
          const data = JSON.parse((event as MessageEvent).data);
          if (data.new_device_id && data.nonce) {
            setTransferNonces((prev) => ({
              ...prev,
              [data.new_device_id]: data.nonce,
            }));
          }
        } catch {
          // Parse error.
        }
      });

      eventSource.onerror = () => {
        if (eventSource?.readyState === EventSource.CLOSED) {
          eventSource = undefined;
          retryTimer = setTimeout(connectSse, 5000);
        }
      };
    } catch {
      retryTimer = setTimeout(connectSse, 5000);
    }
  };

  createEffect(() => {
    const device = deviceState();
    if (!device?.deviceId) return;

    void refetchPending();
    connectSse();

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
