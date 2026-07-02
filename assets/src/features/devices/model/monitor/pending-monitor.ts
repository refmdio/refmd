import {
  createContext,
  createEffect,
  createSignal,
  onCleanup,
  useContext,
  type Accessor,
} from "solid-js";
import {
  joinUserSecurityNotifications,
  SecurityNotificationsJoinError,
} from "@/shared/lib/security/notification-channel";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import { devicesApi, securityNotificationsApi } from "@/shared/api";
import type { SecurityNotificationInfo } from "@/shared/api/security-notifications";
import { authState, deviceState } from "@/entities/session";
import { getAuthTransportBackoffMs } from "@/shared/lib/ws/transport-coordinator";

interface KekRotationNeeded {
  workspace_id: string;
  current_kek_version: number;
}

const DOCUMENT_REMOTE_CONTENT_READY_EVENT = "refmd:document-remote-content-ready";
const DOCUMENT_ROUTE_MONITOR_STARTUP_TIMEOUT_MS = 3_500;
const DOCUMENT_ROUTE_MONITOR_IDLE_TIMEOUT_MS = 1_000;

interface PendingDeviceContextValue {
  pendingDevices: Accessor<DeviceRegistrationInfo[]>;
  pendingCount: Accessor<number>;
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
  const [securityNotifications, setSecurityNotifications] = createSignal<
    readonly SecurityNotificationInfo[]
  >([]);
  const [currentDialog, setCurrentDialog] = createSignal<DeviceRegistrationInfo | null>(null);
  const [approvalError, setApprovalError] = createSignal<string | null>(null);
  const [kekRotationsNeeded, setKekRotationsNeeded] = createSignal<KekRotationNeeded[]>([]);
  const dismissed = new Set<string>();
  const seen = new Set<string>();

  let securityNotificationChannel: { dispose: () => void } | undefined;
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let startupTimer: ReturnType<typeof setTimeout> | undefined;
  let startupIdleTimer: ReturnType<typeof setTimeout> | undefined;
  let startupIdleHandle: number | undefined;
  let startupReadyListener: (() => void) | undefined;
  let expiryTimers: ReturnType<typeof setTimeout>[] = [];
  let connectionGeneration = 0;
  let startupGeneration = 0;

  const pendingCount = () => actionRequiredSecurityNotificationCount(securityNotifications());

  const refetchPending = async () => {
    try {
      const res = await devicesApi.listRegistrations();
      setPendingDevices(res.devices);
      setKekRotationsNeeded([]);
    } catch {
      // Silently ignore. Device events will keep state updated.
    }

    try {
      setSecurityNotifications(await securityNotificationsApi.list());
    } catch {
      // Realtime events remain a fast path; the next reconnect/startup will retry the durable inbox.
    }
  };

  const showApprovalDialog = (device: DeviceRegistrationInfo) => {
    setApprovalError(null);
    setCurrentDialog(device);
  };

  const clearConnectionState = () => {
    connectionGeneration += 1;
    const activeEvents = securityNotificationChannel;
    securityNotificationChannel = undefined;
    activeEvents?.dispose();
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = undefined;
    }
  };

  const clearStartupSchedule = () => {
    if (startupTimer) {
      clearTimeout(startupTimer);
      startupTimer = undefined;
    }
    if (startupIdleTimer) {
      clearTimeout(startupIdleTimer);
      startupIdleTimer = undefined;
    }
    if (
      startupIdleHandle !== undefined &&
      typeof window !== "undefined" &&
      "cancelIdleCallback" in window
    ) {
      window.cancelIdleCallback(startupIdleHandle);
      startupIdleHandle = undefined;
    }
    startupReadyListener?.();
    startupReadyListener = undefined;
  };

  const scheduleReconnect = (generation: number) => {
    if (generation !== connectionGeneration) return;

    if (!retryTimer) {
      const delay = Math.max(5000, getAuthTransportBackoffMs());
      retryTimer = setTimeout(() => {
        retryTimer = undefined;
        if (generation === connectionGeneration) {
          connectSecurityNotifications();
        }
      }, delay);
    }
  };

  const connectSecurityNotifications = () => {
    clearConnectionState();
    const generation = connectionGeneration;

    const auth = authState();
    if (!auth) return;

    joinUserSecurityNotifications(auth.user.id, {
      onPendingDeviceCreated: () => {
        void refetchPending();
      },
      onPendingDeviceRemoved: () => {
        void refetchPending();
      },
      onKekRotationNeeded: (data) => {
        void refetchPending();
        const workspaceId = typeof data.workspace_id === "string" ? data.workspace_id : null;
        const currentKekVersion =
          typeof data.current_kek_version === "number" ? data.current_kek_version : 0;

        if (workspaceId) {
          setKekRotationsNeeded((prev) => {
            if (prev.some((rotation) => rotation.workspace_id === workspaceId)) {
              return prev;
            }
            return [
              ...prev,
              {
                workspace_id: workspaceId,
                current_kek_version: currentKekVersion,
              },
            ];
          });
        }
      },
      onPluginConsentRequired: () => {
        void refetchPending();
      },
      onClose: () => scheduleReconnect(generation),
      onError: () => scheduleReconnect(generation),
    })
      .then((handle) => {
        if (generation !== connectionGeneration) {
          handle.dispose();
          return;
        }
        securityNotificationChannel = handle;
      })
      .catch((error) => {
        if (
          error instanceof SecurityNotificationsJoinError &&
          error.reason === "existing_device_required"
        ) {
          return;
        }
        scheduleReconnect(generation);
      });
  };

  const scheduleStartup = (generation: number) => {
    clearStartupSchedule();
    const start = () => {
      if (generation !== startupGeneration) return;
      void refetchPending();
      connectSecurityNotifications();
    };

    if (!shouldDeferDocumentRouteMonitorStartup()) {
      start();
      return;
    }

    const scheduleIdleStart = () => {
      if (generation !== startupGeneration) return;
      clearStartupSchedule();
      if (typeof window !== "undefined" && "requestIdleCallback" in window) {
        startupIdleHandle = window.requestIdleCallback(start, {
          timeout: DOCUMENT_ROUTE_MONITOR_IDLE_TIMEOUT_MS,
        });
      } else {
        startupIdleTimer = setTimeout(start, DOCUMENT_ROUTE_MONITOR_IDLE_TIMEOUT_MS);
      }
    };
    const handleReady = () => scheduleIdleStart();

    if (typeof window === "undefined") {
      start();
      return;
    }

    window.addEventListener(DOCUMENT_REMOTE_CONTENT_READY_EVENT, handleReady, { once: true });
    startupReadyListener = () => {
      window.removeEventListener(DOCUMENT_REMOTE_CONTENT_READY_EVENT, handleReady);
    };
    startupTimer = setTimeout(scheduleIdleStart, DOCUMENT_ROUTE_MONITOR_STARTUP_TIMEOUT_MS);
  };

  createEffect(() => {
    const auth = authState();
    const device = deviceState();
    if (!auth || !device?.deviceId) {
      clearStartupSchedule();
      clearConnectionState();
      return;
    }

    startupGeneration += 1;
    scheduleStartup(startupGeneration);

    onCleanup(() => {
      startupGeneration += 1;
      clearStartupSchedule();
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
    startupGeneration += 1;
    clearStartupSchedule();
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

function shouldDeferDocumentRouteMonitorStartup(): boolean {
  return typeof window !== "undefined" && window.location.pathname.startsWith("/document/");
}

export function actionRequiredSecurityNotificationCount(
  notifications: readonly SecurityNotificationInfo[],
  nowMs = Date.now(),
): number {
  return notifications.filter((notification) => {
    if (notification.severity !== "action_required") return false;
    if (notification.read_at || notification.dismissed_at || notification.acted_at) return false;
    if (!notification.expires_at) return true;
    return new Date(notification.expires_at).getTime() > nowMs;
  }).length;
}
