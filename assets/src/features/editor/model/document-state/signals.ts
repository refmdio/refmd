import { createSignal } from "solid-js";
import {
  awarenessSignals,
  documentStates,
  errorSignals,
  readOnlySignals,
  reauthSignals,
  rollbackSignals,
  shareReentrySignals,
  syncPausedSignals,
} from "./registry";
import type { Awareness } from "y-protocols/awareness";

function getErrorSignal(stateKey: string) {
  let signal = errorSignals.get(stateKey);
  if (!signal) {
    signal = createSignal<string | null>(null);
    errorSignals.set(stateKey, signal);
  }
  return signal;
}

function getReauthSignal(stateKey: string) {
  let signal = reauthSignals.get(stateKey);
  if (!signal) {
    signal = createSignal(false);
    reauthSignals.set(stateKey, signal);
  }
  return signal;
}

function getRollbackSignal(stateKey: string) {
  let signal = rollbackSignals.get(stateKey);
  if (!signal) {
    signal = createSignal<string | null>(null);
    rollbackSignals.set(stateKey, signal);
  }
  return signal;
}

function getShareReentrySignal(stateKey: string) {
  let signal = shareReentrySignals.get(stateKey);
  if (!signal) {
    signal = createSignal(false);
    shareReentrySignals.set(stateKey, signal);
  }
  return signal;
}

function getAwarenessSignal(stateKey: string) {
  let signal = awarenessSignals.get(stateKey);
  if (!signal) {
    signal = createSignal<Awareness | null>(null);
    awarenessSignals.set(stateKey, signal);
  }
  return signal;
}

function getReadOnlySignal(stateKey: string) {
  let signal = readOnlySignals.get(stateKey);
  if (!signal) {
    signal = createSignal(documentStates.get(stateKey)?.readOnly ?? false);
    readOnlySignals.set(stateKey, signal);
  }
  return signal;
}

function getSyncPausedSignal(stateKey: string) {
  let signal = syncPausedSignals.get(stateKey);
  if (!signal) {
    signal = createSignal(documentStates.get(stateKey)?._syncPaused ?? false);
    syncPausedSignals.set(stateKey, signal);
  }
  return signal;
}

export function clearDocumentSignals(stateKey: string): void {
  errorSignals.delete(stateKey);
  awarenessSignals.delete(stateKey);
  reauthSignals.delete(stateKey);
  shareReentrySignals.delete(stateKey);
  rollbackSignals.delete(stateKey);
  readOnlySignals.delete(stateKey);
  syncPausedSignals.delete(stateKey);
}

export function getDocumentError(stateKey: string): string | null {
  return getErrorSignal(stateKey)[0]();
}

export function setDocumentError(stateKey: string, error: string): void {
  getErrorSignal(stateKey)[1](error);
  const state = documentStates.get(stateKey);
  if (state) state.error = error;
}

export function getDocumentReadOnly(stateKey: string): boolean {
  return getReadOnlySignal(stateKey)[0]();
}

export function setDocumentReadOnly(stateKey: string, readOnly: boolean): void {
  const state = documentStates.get(stateKey);
  if (state) state.readOnly = readOnly;
  getReadOnlySignal(stateKey)[1](readOnly);
}

export function getDocumentSyncPaused(stateKey: string): boolean {
  return getSyncPausedSignal(stateKey)[0]();
}

export function setDocumentSyncPaused(stateKey: string, paused: boolean): void {
  const state = documentStates.get(stateKey);
  if (state) state._syncPaused = paused;
  getSyncPausedSignal(stateKey)[1](paused);
}

export function needsReauth(stateKey: string): boolean {
  return getReauthSignal(stateKey)[0]();
}

export function requestReauth(stateKey: string): Promise<void> {
  getReauthSignal(stateKey)[1](true);
  return new Promise<void>((resolve) => {
    const state = documentStates.get(stateKey);
    if (state) {
      state._reauthResolvers.push(resolve);
    } else {
      resolve();
    }
  });
}

export function completeReauth(stateKey: string): void {
  getReauthSignal(stateKey)[1](false);
  const state = documentStates.get(stateKey);
  if (!state || state._reauthResolvers.length === 0) return;
  for (const resolve of state._reauthResolvers) resolve();
  state._reauthResolvers = [];
}

export function needsShareReentry(stateKey: string): boolean {
  return getShareReentrySignal(stateKey)[0]();
}

export function requestShareReentry(stateKey: string): void {
  getShareReentrySignal(stateKey)[1](true);
}

export function clearShareReentry(stateKey: string): void {
  getShareReentrySignal(stateKey)[1](false);
}

export function getRollbackWarning(stateKey: string): string | null {
  return getRollbackSignal(stateKey)[0]();
}

export function requestRollbackApproval(stateKey: string, message: string): Promise<void> {
  getRollbackSignal(stateKey)[1](message);
  return new Promise<void>((resolve) => {
    const state = documentStates.get(stateKey);
    if (state) {
      state._rollbackResolvers.push(resolve);
    } else {
      resolve();
    }
  });
}

export function approveRollback(stateKey: string): void {
  getRollbackSignal(stateKey)[1](null);
  const state = documentStates.get(stateKey);
  if (!state || state._rollbackResolvers.length === 0) return;
  for (const resolve of state._rollbackResolvers) resolve();
  state._rollbackResolvers = [];
}

export function getDocumentAwareness(stateKey: string): Awareness | null {
  return getAwarenessSignal(stateKey)[0]();
}

export function notifyAwarenessReady(stateKey: string): void {
  const state = documentStates.get(stateKey);
  if (state?.awareness) {
    getAwarenessSignal(stateKey)[1](state.awareness);
  }
}
