import { Socket } from "phoenix";
import { ApiError } from "@/shared/api/core";
import { authApi } from "@/shared/api/auth";
import { getPreferredSessionScope } from "@/shared/lib/auth/session-scope";
import { isAuthUnauthorizedError } from "@/shared/lib/auth/unauthorized";
import { setWsConnected } from "@/shared/lib/offline/offline-state";
import {
  clearAuthTransportNetworkFailure,
  getAuthTransportBackoffMs,
  getRetryMsFromUnknown,
  recordAuthTransportNetworkFailure,
  recordAuthTransportRateLimit,
  resetAuthTransportCoordinator,
  runAuthTransportSingleFlight,
  waitForAuthTransport,
} from "./transport-coordinator";

type SocketScope = "user" | "share";

interface SocketScopeState {
  socket: Socket | null;
  cachedWsToken: string | null;
  cachedWsTokenIssuedAt: number;
  scheduledWsTokenRefresh: ReturnType<typeof setTimeout> | null;
}

const scopeStates = new Map<SocketScope, SocketScopeState>();

const WS_TOKEN_REFRESH_AFTER_MS = 240_000;
let pageUnloading = false;
let lifecycleHandlersInstalled = false;

function clearScheduledWsTokenRefresh(scopeState: SocketScopeState): void {
  if (!scopeState.scheduledWsTokenRefresh) return;
  clearTimeout(scopeState.scheduledWsTokenRefresh);
  scopeState.scheduledWsTokenRefresh = null;
}

function disconnectSocketsForPageUnload(): void {
  pageUnloading = true;
  for (const scopeState of scopeStates.values()) {
    clearScheduledWsTokenRefresh(scopeState);
    const activeSocket = scopeState.socket;
    scopeState.socket = null;
    activeSocket?.disconnect();
  }
}

function ensureLifecycleHandlersInstalled(): void {
  if (lifecycleHandlersInstalled || typeof window === "undefined") return;
  lifecycleHandlersInstalled = true;
  window.addEventListener("pagehide", disconnectSocketsForPageUnload, { once: true });
  window.addEventListener("beforeunload", disconnectSocketsForPageUnload, { once: true });
}

function resolveSocketScope(scope?: SocketScope): SocketScope {
  return scope ?? (getPreferredSessionScope() === "share" ? "share" : "user");
}

function getScopeState(scope: SocketScope): SocketScopeState {
  let state = scopeStates.get(scope);
  if (!state) {
    state = {
      socket: null,
      cachedWsToken: null,
      cachedWsTokenIssuedAt: 0,
      scheduledWsTokenRefresh: null,
    };
    scopeStates.set(scope, state);
  }
  return state;
}

function invalidateCachedWsToken(scopeState: SocketScopeState): void {
  scopeState.cachedWsToken = null;
  scopeState.cachedWsTokenIssuedAt = 0;
}

function hasUsableCachedWsToken(scopeState: SocketScopeState): boolean {
  return (
    !!scopeState.cachedWsToken &&
    Date.now() - scopeState.cachedWsTokenIssuedAt < WS_TOKEN_REFRESH_AFTER_MS
  );
}

function isUnauthorized(error: unknown): boolean {
  return isAuthUnauthorizedError(error) || (error instanceof ApiError && error.status === 401);
}

export async function refreshPhoenixWsToken(scopeInput?: SocketScope): Promise<void> {
  const scope = resolveSocketScope(scopeInput);
  const scopeState = getScopeState(scope);
  await runAuthTransportSingleFlight(`ws-token:${scope}`, async () => {
    await waitForAuthTransport();
    try {
      const result = await authApi.wsToken({ sessionScope: scope });
      scopeState.cachedWsToken = result.token;
      scopeState.cachedWsTokenIssuedAt = Date.now();
      clearAuthTransportNetworkFailure();
      if (scopeState.socket && !scopeState.socket.isConnected()) {
        scopeState.socket.connect();
      }
    } catch (error) {
      const retryMs = getRetryMsFromUnknown(error);
      if (retryMs !== null) {
        recordAuthTransportRateLimit(retryMs);
      } else if (error instanceof TypeError) {
        recordAuthTransportNetworkFailure();
      }
      invalidateCachedWsToken(scopeState);
      throw error;
    }
  });
}

export async function ensurePhoenixWsToken(scope?: SocketScope): Promise<void> {
  const resolvedScope = resolveSocketScope(scope);
  if (!hasUsableCachedWsToken(getScopeState(resolvedScope))) {
    await refreshPhoenixWsToken(resolvedScope);
  }
}

export function getPhoenixSocketUrl(): string {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${location.host}/api/socket`;
}

function schedulePhoenixWsTokenRefresh(
  scope: SocketScope,
  options: { forceRefresh?: boolean } = {},
): void {
  const scopeState = getScopeState(scope);
  if (options.forceRefresh) {
    invalidateCachedWsToken(scopeState);
  }
  if (hasUsableCachedWsToken(scopeState)) return;
  if (scopeState.scheduledWsTokenRefresh) return;

  const delay = getAuthTransportBackoffMs();
  scopeState.scheduledWsTokenRefresh = setTimeout(() => {
    scopeState.scheduledWsTokenRefresh = null;
    refreshPhoenixWsToken(scope).catch((error) => {
      if (isUnauthorized(error)) {
        invalidateCachedWsToken(scopeState);
        setWsConnected(false);
        return;
      }
      schedulePhoenixWsTokenRefresh(scope);
    });
  }, delay);
}

function discardPhoenixSocket(scope: SocketScope, activeSocket: Socket): void {
  const scopeState = getScopeState(scope);
  if (scopeState.socket !== activeSocket) return;
  scopeState.socket = null;
  activeSocket.disconnect();
}

export function getOrCreatePhoenixSocket(scopeInput?: SocketScope): Socket {
  ensureLifecycleHandlersInstalled();
  const scope = resolveSocketScope(scopeInput);
  const scopeState = getScopeState(scope);
  if (scopeState.socket) {
    if (!scopeState.socket.isConnected()) {
      setWsConnected(false);
      if (scopeState.cachedWsToken) {
        scopeState.socket.connect();
      } else {
        schedulePhoenixWsTokenRefresh(scope);
      }
    } else {
      setWsConnected(true);
    }
    return scopeState.socket;
  }

  const activeSocket = new Socket(getPhoenixSocketUrl(), {
    params: () => ({ token: scopeState.cachedWsToken }),
    reconnectAfterMs: (tries: number) => Math.min(100 * Math.pow(1.8, tries), 30000),
  });

  scopeState.socket = activeSocket;
  setWsConnected(false);
  activeSocket.onOpen(() => {
    if (scopeState.socket !== activeSocket) return;
    clearAuthTransportNetworkFailure();
    setWsConnected(true);
  });
  activeSocket.onError(() => {
    if (pageUnloading) return;
    if (scopeState.socket !== activeSocket) return;
    setWsConnected(false);
    recordAuthTransportNetworkFailure();
    discardPhoenixSocket(scope, activeSocket);
    schedulePhoenixWsTokenRefresh(scope, { forceRefresh: true });
  });
  activeSocket.onClose(() => {
    if (pageUnloading) return;
    if (scopeState.socket !== activeSocket) return;
    setWsConnected(false);
    recordAuthTransportNetworkFailure();
    discardPhoenixSocket(scope, activeSocket);
    schedulePhoenixWsTokenRefresh(scope, { forceRefresh: true });
  });
  if (scopeState.cachedWsToken) {
    activeSocket.connect();
  } else {
    schedulePhoenixWsTokenRefresh(scope);
  }
  return activeSocket;
}

export function createTemporaryPhoenixSocket(scopeInput?: SocketScope): Socket {
  const scope = resolveSocketScope(scopeInput);
  const scopeState = getScopeState(scope);
  const tempSocket = new Socket(getPhoenixSocketUrl(), {
    params: () => ({ token: scopeState.cachedWsToken }),
    reconnectAfterMs: () => Infinity,
  });
  tempSocket.connect();
  return tempSocket;
}

export function isPhoenixSocketConnected(target: Socket): boolean;
export function isPhoenixSocketConnected(): boolean;
export function isPhoenixSocketConnected(target?: Socket): boolean {
  if (target !== undefined) return target.isConnected();
  for (const scopeState of scopeStates.values()) {
    if (scopeState.socket?.isConnected()) return true;
  }
  return false;
}

export function resetPhoenixSocketState(scopeInput?: SocketScope): void {
  const states =
    scopeInput === undefined
      ? [...scopeStates.values()]
      : [getScopeState(resolveSocketScope(scopeInput))];

  for (const scopeState of states) {
    const activeSocket = scopeState.socket;
    scopeState.socket = null;
    if (activeSocket) {
      activeSocket.disconnect();
    }
    invalidateCachedWsToken(scopeState);
    clearScheduledWsTokenRefresh(scopeState);
  }
  if (scopeInput === undefined) {
    resetAuthTransportCoordinator();
  }
  setWsConnected(false);
}
