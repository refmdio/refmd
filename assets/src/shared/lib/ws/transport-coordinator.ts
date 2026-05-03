import { setAuthTransportReason } from "@/shared/lib/offline/offline-state";

const MAX_NETWORK_BACKOFF_MS = 30_000;
const JITTER_MS = 200;

let rateLimitedUntil = 0;
let networkUnavailableUntil = 0;
let networkFailureDelayMs = 0;
let offlineReasonTimer: ReturnType<typeof setTimeout> | null = null;
const singleFlights = new Map<string, Promise<unknown>>();

function createAbortError(): Error {
  const error = new Error("request_aborted");
  error.name = "AbortError";
  return error;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(createAbortError());
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timeout);
      reject(createAbortError());
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export function getAuthTransportBackoffMs(): number {
  return Math.max(0, Math.max(rateLimitedUntil, networkUnavailableUntil) - Date.now());
}

function clearOfflineReasonTimer(): void {
  if (!offlineReasonTimer) return;
  clearTimeout(offlineReasonTimer);
  offlineReasonTimer = null;
}

function syncOfflineReason(): void {
  clearOfflineReasonTimer();

  const now = Date.now();
  if (rateLimitedUntil > now && rateLimitedUntil >= networkUnavailableUntil) {
    setAuthTransportReason("auth_backoff");
  } else if (networkUnavailableUntil > now) {
    setAuthTransportReason("server_unreachable");
  } else {
    setAuthTransportReason(null);
    return;
  }

  const remaining = getAuthTransportBackoffMs();
  if (remaining > 0) {
    offlineReasonTimer = setTimeout(() => {
      offlineReasonTimer = null;
      syncOfflineReason();
    }, remaining + JITTER_MS);
  }
}

export async function waitForAuthTransport(signal?: AbortSignal): Promise<void> {
  while (true) {
    const remaining = getAuthTransportBackoffMs();
    if (remaining <= 0) {
      syncOfflineReason();
      return;
    }
    await sleep(remaining + Math.random() * JITTER_MS, signal);
  }
}

export function recordAuthTransportRateLimit(retryMs: number): void {
  const until = Date.now() + Math.max(1_000, retryMs);
  if (until > rateLimitedUntil) {
    rateLimitedUntil = until;
  }
  syncOfflineReason();
}

export function recordAuthTransportNetworkFailure(): void {
  networkFailureDelayMs = Math.min(
    networkFailureDelayMs === 0 ? 1_000 : networkFailureDelayMs * 1.8,
    MAX_NETWORK_BACKOFF_MS,
  );
  networkUnavailableUntil = Math.max(networkUnavailableUntil, Date.now() + networkFailureDelayMs);
  syncOfflineReason();
}

export function clearAuthTransportNetworkFailure(): void {
  networkFailureDelayMs = 0;
  networkUnavailableUntil = 0;
  syncOfflineReason();
}

export function resetAuthTransportCoordinator(): void {
  rateLimitedUntil = 0;
  networkUnavailableUntil = 0;
  networkFailureDelayMs = 0;
  clearOfflineReasonTimer();
  setAuthTransportReason(null);
  singleFlights.clear();
}

export async function runAuthTransportSingleFlight<T>(
  key: string,
  task: () => Promise<T>,
): Promise<T> {
  const existing = singleFlights.get(key);
  if (existing) {
    return existing as Promise<T>;
  }

  const holder: { promise?: Promise<T> } = {};
  const trackedPromise = task().finally(() => {
    if (singleFlights.get(key) === holder.promise) {
      singleFlights.delete(key);
    }
  });
  holder.promise = trackedPromise;
  singleFlights.set(key, trackedPromise);
  return trackedPromise;
}

export function getRetryMsFromUnknown(error: unknown): number | null {
  if (!(error instanceof Error)) return null;

  const maybeApiError = error as Error & {
    status?: number;
    body?: { retry_after?: string | number };
  };
  if (maybeApiError.status !== 429) return null;

  const retryAfter = maybeApiError.body?.retry_after;
  if (typeof retryAfter === "number" && retryAfter > 0) {
    return retryAfter * 1000;
  }
  if (typeof retryAfter === "string") {
    const parsed = parseFloat(retryAfter);
    if (!Number.isNaN(parsed) && parsed > 0) {
      return parsed * 1000;
    }
  }
  return 1_000;
}
