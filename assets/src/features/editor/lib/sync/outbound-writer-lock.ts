import { setDocumentReadOnly } from "../../model/document-state/signals";
import type { DocumentState } from "../../model/document-state/types";
import { authState } from "@/entities/session";
import { notifyUxLimitResolved, retainUxLimitNotice } from "./ux-limit-notice";

const LOCK_TTL_MS = 10_000;
const HEARTBEAT_MS = 2_000;
const RETRY_MS = 500;
const CHANNEL_NAME = "refmd:document-writer-lock";
const OWNER_STORAGE_KEY = "refmd:document-writer-lock-owner";
const TAB_STORAGE_KEY = "refmd:document-writer-lock-tab";

function createOwnerId(): string {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function loadOwnerId(): string {
  try {
    const existing = sessionStorage.getItem(OWNER_STORAGE_KEY);
    const ownerId = existing ?? createOwnerId();
    sessionStorage.setItem(OWNER_STORAGE_KEY, ownerId);
    return ownerId;
  } catch {
    return createOwnerId();
  }
}

const OWNER_ID = loadOwnerId();
const TAB_ID = loadTabId();
const INSTANCE_ID = createOwnerId();

interface WriterLockRecord {
  tabId?: string;
  ownerId: string;
  instanceId?: string;
  leaseId?: string;
  expiresAt: number;
}

interface WriterLockHandle {
  acquired: boolean;
  dispose: () => void;
}

interface WriterLockOptions {
  onAcquired?: () => void;
}

interface WriterLockBroadcastMessage {
  type: "released" | "changed";
  key: string;
  ownerId: string;
  instanceId: string;
}

function getOwnerId(): string {
  return OWNER_ID;
}

function loadTabId(): string {
  try {
    const existing = sessionStorage.getItem(TAB_STORAGE_KEY);
    const tabId = existing ?? createOwnerId();
    sessionStorage.setItem(TAB_STORAGE_KEY, tabId);
    return tabId;
  } catch {
    return createOwnerId();
  }
}

function getTabId(): string {
  return TAB_ID;
}

function getInstanceId(): string {
  return INSTANCE_ID;
}

function lockKey(documentId: string, principalKey: string): string {
  return `refmd:document-writer-lock:${documentId}:${principalKey}`;
}

function writerPrincipalKey(state: DocumentState, fallbackSigningKeyId: string): string {
  if (state.access.kind === "share") {
    return `share:${state.access.participantPrincipalId}`;
  }

  const userId = authState()?.user.id;
  return userId ? `user:${userId}` : `device:${fallbackSigningKeyId}`;
}

function readLock(key: string): WriterLockRecord | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<WriterLockRecord>;
    if (typeof parsed.ownerId !== "string" || typeof parsed.expiresAt !== "number") return null;
    return {
      tabId: typeof parsed.tabId === "string" ? parsed.tabId : undefined,
      ownerId: parsed.ownerId,
      instanceId: typeof parsed.instanceId === "string" ? parsed.instanceId : undefined,
      leaseId: typeof parsed.leaseId === "string" ? parsed.leaseId : undefined,
      expiresAt: parsed.expiresAt,
    };
  } catch {
    return null;
  }
}

function writeLock(
  key: string,
  ownerId: string,
  tabId: string,
  instanceId: string,
  leaseId: string,
): void {
  localStorage.setItem(
    key,
    JSON.stringify({
      tabId,
      ownerId,
      instanceId,
      leaseId,
      expiresAt: Date.now() + LOCK_TTL_MS,
    }),
  );
}

function ownsLock(key: string, ownerId: string, instanceId: string, leaseId: string): boolean {
  const lock = readLock(key);
  return lock?.ownerId === ownerId && lock.instanceId === instanceId && lock.leaseId === leaseId;
}

function canAcquireLock(key: string, ownerId: string, tabId: string): boolean {
  const existing = readLock(key);
  return (
    !existing ||
    existing.ownerId === ownerId ||
    existing.tabId === tabId ||
    existing.expiresAt <= Date.now()
  );
}

export function acquireDocumentWriterLock(
  documentId: string,
  signingKeyId: string,
  state: DocumentState,
  options: WriterLockOptions = {},
): WriterLockHandle {
  const ownerId = getOwnerId();
  const tabId = getTabId();
  const instanceId = getInstanceId();
  const leaseId = createOwnerId();
  const key = lockKey(documentId, writerPrincipalKey(state, signingKeyId));
  let acquired = false;
  let disposed = false;
  let heartbeat: ReturnType<typeof setInterval> | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  let lockNoticeRelease: (() => void) | null = null;
  const broadcast =
    typeof BroadcastChannel !== "undefined" ? new BroadcastChannel(CHANNEL_NAME) : null;

  const clearHeartbeat = () => {
    if (heartbeat) {
      clearInterval(heartbeat);
      heartbeat = null;
    }
  };

  const clearRetry = () => {
    if (retryTimer) {
      clearTimeout(retryTimer);
      retryTimer = null;
    }
  };

  const showWriterLockNotice = () => {
    if (lockNoticeRelease) return;
    lockNoticeRelease = retainUxLimitNotice(
      `document-writer-lock:${key}`,
      "Editing is paused in this tab.",
      "This document is already open for editing in another tab. Editing will resume here when the other tab releases it.",
    );
  };

  const hideWriterLockNotice = (restored: boolean) => {
    if (!lockNoticeRelease) return;
    lockNoticeRelease();
    lockNoticeRelease = null;
    if (restored) {
      notifyUxLimitResolved("Editing is available in this tab.");
    }
  };

  const loseLock = (retry: boolean) => {
    if (disposed) return;
    acquired = false;
    clearHeartbeat();
    setDocumentReadOnly(state.stateKey, true);
    showWriterLockNotice();
    if (state.autoSync) {
      state.autoSync.dispose();
      state.autoSync = null;
    }
    if (retry) scheduleRetry();
  };

  const startHeartbeat = () => {
    clearHeartbeat();
    heartbeat = setInterval(() => {
      if (!ownsLock(key, ownerId, instanceId, leaseId)) {
        if (isSupersededBySameInstance()) {
          retireSupersededHandle();
          return;
        }
        loseLock(true);
        return;
      }
      writeLock(key, ownerId, tabId, instanceId, leaseId);
    }, HEARTBEAT_MS);
  };

  const tryAcquire = () => {
    if (disposed || acquired || !canAcquireLock(key, ownerId, tabId)) return false;
    writeLock(key, ownerId, tabId, instanceId, leaseId);
    broadcast?.postMessage({
      type: "changed",
      key,
      ownerId,
      instanceId,
    } satisfies WriterLockBroadcastMessage);
    acquired = true;
    clearRetry();
    startHeartbeat();
    setDocumentReadOnly(state.stateKey, false);
    hideWriterLockNotice(true);
    options.onAcquired?.();
    return true;
  };

  function scheduleRetry(): void {
    if (disposed || acquired || retryTimer) return;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (!tryAcquire()) scheduleRetry();
    }, RETRY_MS);
  }

  const onStorage = (event: StorageEvent) => {
    if (event.key !== key) return;
    if (acquired && !ownsLock(key, ownerId, instanceId, leaseId)) {
      if (isSupersededBySameInstance()) {
        retireSupersededHandle();
        return;
      }
      loseLock(true);
      return;
    }
    if (!acquired) {
      tryAcquire();
    }
  };
  window.addEventListener("storage", onStorage);

  const onBroadcast = (event: MessageEvent<WriterLockBroadcastMessage>) => {
    const message = event.data;
    if (!message || message.key !== key || message.instanceId === instanceId) return;
    if (acquired && !ownsLock(key, ownerId, instanceId, leaseId)) {
      loseLock(true);
      return;
    }
    if (!acquired && message.type === "released") {
      tryAcquire();
    }
  };
  broadcast?.addEventListener("message", onBroadcast);

  const releaseOwnedLock = () => {
    if (ownsLock(key, ownerId, instanceId, leaseId)) {
      localStorage.removeItem(key);
      broadcast?.postMessage({
        type: "released",
        key,
        ownerId,
        instanceId,
      } satisfies WriterLockBroadcastMessage);
    }
  };

  function isSupersededBySameInstance(): boolean {
    const lock = readLock(key);
    return lock?.ownerId === ownerId && lock.instanceId === instanceId && lock.leaseId !== leaseId;
  }

  function retireSupersededHandle(): void {
    disposed = true;
    acquired = false;
    clearHeartbeat();
    clearRetry();
    window.removeEventListener("storage", onStorage);
    broadcast?.removeEventListener("message", onBroadcast);
    window.removeEventListener("pagehide", releaseOwnedLock);
    window.removeEventListener("beforeunload", releaseOwnedLock);
    hideWriterLockNotice(false);
    broadcast?.close();
  }
  window.addEventListener("pagehide", releaseOwnedLock);
  window.addEventListener("beforeunload", releaseOwnedLock);

  if (!tryAcquire()) {
    setDocumentReadOnly(state.stateKey, true);
    showWriterLockNotice();
    scheduleRetry();
  }

  return {
    acquired,
    dispose: () => {
      disposed = true;
      clearHeartbeat();
      clearRetry();
      window.removeEventListener("storage", onStorage);
      broadcast?.removeEventListener("message", onBroadcast);
      window.removeEventListener("pagehide", releaseOwnedLock);
      window.removeEventListener("beforeunload", releaseOwnedLock);
      hideWriterLockNotice(false);
      releaseOwnedLock();
      broadcast?.close();
    },
  };
}
