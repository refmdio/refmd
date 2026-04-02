import { createSignal } from "solid-js";

const [networkOnline, setNetworkOnline] = createSignal(
  typeof navigator !== "undefined" ? navigator.onLine : true,
);
const [wsConnected, setWsConnectedInternal] = createSignal(true);

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

export function offlineMode(): boolean {
  return !networkOnline() || !wsConnected();
}

export function offlineReason(): "network" | "ws_disconnect" | null {
  if (!networkOnline()) return "network";
  if (!wsConnected()) return "ws_disconnect";
  return null;
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
