import {
  createContext,
  useContext,
  createSignal,
  createEffect,
  onCleanup,
  Show,
  type ParentComponent,
  type Accessor,
} from "solid-js";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import { devicesApi } from "@/shared/api";
import { deviceState } from "@/shared/lib/auth-state";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { ApproveDeviceDialog } from "./approve-dialog";

export interface KekRotationNeeded {
  workspace_id: string;
  current_kek_version: number;
}

export interface PendingDeviceContextValue {
  pendingDevices: Accessor<DeviceRegistrationInfo[]>;
  pendingCount: Accessor<number>;
  transferNonces: Accessor<Record<string, string>>;
  kekRotationsNeeded: Accessor<KekRotationNeeded[]>;
  showApprovalDialog: (device: DeviceRegistrationInfo) => void;
  refetchPending: () => Promise<void>;
}

const PendingDeviceContext = createContext<PendingDeviceContextValue>();

export function usePendingDevices(): PendingDeviceContextValue {
  const ctx = useContext(PendingDeviceContext);
  if (!ctx) {
    throw new Error("usePendingDevices must be used within PendingDeviceMonitor");
  }
  return ctx;
}

export const PendingDeviceMonitor: ParentComponent = (props) => {
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
    } catch {
      // Silently ignore — SSE will keep state updated
    }
  };

  const showApprovalDialog = (device: DeviceRegistrationInfo) => {
    setCurrentDialog(device);
  };

  const connectSSE = () => {
    if (eventSource) {
      eventSource.close();
      eventSource = undefined;
    }
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = undefined;
    }

    try {
      eventSource = new EventSource("/api/devices/events");

      eventSource.addEventListener("pending_device_created", () => {
        refetchPending();
      });

      eventSource.addEventListener("pending_device_removed", () => {
        refetchPending();
      });

      eventSource.addEventListener("kek_rotation_needed", (event) => {
        try {
          const data = JSON.parse((event as MessageEvent).data);
          if (data.workspace_id) {
            setKekRotationsNeeded((prev) => {
              if (prev.some((r) => r.workspace_id === data.workspace_id)) return prev;
              return [...prev, { workspace_id: data.workspace_id, current_kek_version: data.current_kek_version }];
            });
          }
        } catch {
          // Parse error
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
          // Parse error
        }
      });

      eventSource.onerror = () => {
        if (eventSource?.readyState === EventSource.CLOSED) {
          // Permanent failure (e.g., 403 — session not yet device-bound).
          // Retry after delay; other PoP requests will bind the session.
          eventSource = undefined;
          retryTimer = setTimeout(connectSSE, 5000);
        }
        // If CONNECTING, browser is auto-reconnecting — let it
      };
    } catch {
      retryTimer = setTimeout(connectSSE, 5000);
    }
  };

  // Activate when device state becomes available
  createEffect(() => {
    const device = deviceState();
    if (!device?.deviceId) return;

    refetchPending();
    connectSSE();

    onCleanup(() => {
      if (eventSource) {
        eventSource.close();
        eventSource = undefined;
      }
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = undefined;
      }
    });
  });

  // Schedule refetch when pending devices expire (TTL-based cleanup)
  createEffect(() => {
    const devices = pendingDevices();
    for (const timer of expiryTimers) clearTimeout(timer);
    expiryTimers = [];

    for (const d of devices) {
      const ms = new Date(d.expires_at).getTime() - Date.now();
      if (ms > 0) {
        expiryTimers.push(setTimeout(() => refetchPending(), ms + 500));
      }
    }
  });

  // Dismiss dialog if the pending device was removed (e.g. rejected/expired)
  createEffect(() => {
    const dialog = currentDialog();
    if (!dialog) return;
    const devices = pendingDevices();
    if (!devices.some((d) => d.id === dialog.id)) {
      setCurrentDialog(null);
    }
  });

  // Auto-show dialog for new unseen/undismissed pending devices
  createEffect(() => {
    const devices = pendingDevices();
    if (devices.length === 0 || currentDialog()) return;

    const newDevice = devices.find(
      (d) => !seen.has(d.id) && !dismissed.has(d.id),
    );
    if (newDevice) {
      seen.add(newDevice.id);
      setCurrentDialog(newDevice);
    }
  });

  const handleDialogClose = () => {
    const dialog = currentDialog();
    if (dialog) dismissed.add(dialog.id);
    setCurrentDialog(null);
  };

  const handleApproved = () => {
    setCurrentDialog(null);
    refetchPending();
  };

  const contextValue: PendingDeviceContextValue = {
    pendingDevices,
    pendingCount,
    transferNonces,
    kekRotationsNeeded,
    showApprovalDialog,
    refetchPending,
  };

  return (
    <PendingDeviceContext.Provider value={contextValue}>
      {props.children}
      <Show when={currentDialog()}>
        {(target) => (
          <ApproveDeviceDialog
            device={target()}
            transferNonce={transferNonces()[target().id] ?? null}
            onClose={handleDialogClose}
            onApproved={handleApproved}
            onError={(msg) => {
              setCurrentDialog(null);
              setApprovalError(msg);
            }}
          />
        )}
      </Show>
      <Show when={approvalError()}>
        <div class="fixed bottom-4 right-4 z-50 max-w-md">
          <Alert variant="destructive">
            <AlertDescription>{approvalError()}</AlertDescription>
          </Alert>
        </div>
      </Show>
    </PendingDeviceContext.Provider>
  );
};
