import { createSignal } from "solid-js";

export type OfflineReason = "network" | "server_unreachable" | "auth_backoff" | "ws_disconnect";

const [networkOnline, setNetworkOnline] = createSignal(
  typeof navigator !== "undefined" ? navigator.onLine : true,
);
const [wsConnected, setWsConnectedInternal] = createSignal(false);
const [authTransportReason, setAuthTransportReasonInternal] = createSignal<
  "server_unreachable" | "auth_backoff" | null
>(null);

if (typeof window !== "undefined") {
  window.addEventListener("online", () => {
    setNetworkOnline(true);
    notifyOfflineListeners();
  });
  window.addEventListener("offline", () => {
    setNetworkOnline(false);
    notifyOfflineListeners();
  });
}

export function setWsConnected(connected: boolean): void {
  setWsConnectedInternal(connected);
  notifyOfflineListeners();
}

export function setAuthTransportReason(reason: "server_unreachable" | "auth_backoff" | null): void {
  setAuthTransportReasonInternal(reason);
  notifyOfflineListeners();
}

export function isNetworkOnline(): boolean {
  return networkOnline();
}

export function isWsConnected(): boolean {
  return wsConnected();
}

export function offlineMode(): boolean {
  return offlineReason() !== null;
}

export function offlineReason(): OfflineReason | null {
  if (!networkOnline()) return "network";
  const transportReason = authTransportReason();
  if (transportReason) return transportReason;
  if (!wsConnected()) return "ws_disconnect";
  return null;
}

export function shouldPreferOfflineCache(): boolean {
  const reason = offlineReason();
  return reason === "network" || reason === "server_unreachable" || reason === "auth_backoff";
}

type OfflineChangeCallback = (isOffline: boolean) => void;
const listeners = new Set<OfflineChangeCallback>();

let prevOffline = false;

function notifyOfflineListeners(): void {
  const current = offlineMode();
  if (current !== prevOffline) {
    prevOffline = current;
    for (const cb of listeners) {
      cb(current);
    }
  }
}

export function onOfflineModeChange(callback: OfflineChangeCallback): () => void {
  listeners.add(callback);
  return () => {
    listeners.delete(callback);
  };
}
