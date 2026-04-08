import { createSignal } from "solid-js";
import {
  awarenessSignals,
  documentStates,
  errorSignals,
  reauthSignals,
  rollbackSignals,
} from "./registry";
import type { Awareness } from "y-protocols/awareness";

function getErrorSignal(documentId: string) {
  let signal = errorSignals.get(documentId);
  if (!signal) {
    signal = createSignal<string | null>(null);
    errorSignals.set(documentId, signal);
  }
  return signal;
}

function getReauthSignal(documentId: string) {
  let signal = reauthSignals.get(documentId);
  if (!signal) {
    signal = createSignal(false);
    reauthSignals.set(documentId, signal);
  }
  return signal;
}

function getRollbackSignal(documentId: string) {
  let signal = rollbackSignals.get(documentId);
  if (!signal) {
    signal = createSignal<string | null>(null);
    rollbackSignals.set(documentId, signal);
  }
  return signal;
}

function getAwarenessSignal(documentId: string) {
  let signal = awarenessSignals.get(documentId);
  if (!signal) {
    signal = createSignal<Awareness | null>(null);
    awarenessSignals.set(documentId, signal);
  }
  return signal;
}

export function clearDocumentSignals(documentId: string): void {
  errorSignals.delete(documentId);
  awarenessSignals.delete(documentId);
  reauthSignals.delete(documentId);
  rollbackSignals.delete(documentId);
}

export function getDocumentError(documentId: string): string | null {
  return getErrorSignal(documentId)[0]();
}

export function setDocumentError(documentId: string, error: string): void {
  getErrorSignal(documentId)[1](error);
  const state = documentStates.get(documentId);
  if (state) state.error = error;
}

export function needsReauth(documentId: string): boolean {
  return getReauthSignal(documentId)[0]();
}

export function requestReauth(documentId: string): Promise<void> {
  getReauthSignal(documentId)[1](true);
  return new Promise<void>((resolve) => {
    const state = documentStates.get(documentId);
    if (state) {
      state._reauthResolvers.push(resolve);
    } else {
      resolve();
    }
  });
}

export function completeReauth(documentId: string): void {
  getReauthSignal(documentId)[1](false);
  const state = documentStates.get(documentId);
  if (!state || state._reauthResolvers.length === 0) return;
  for (const resolve of state._reauthResolvers) resolve();
  state._reauthResolvers = [];
}

export function getRollbackWarning(documentId: string): string | null {
  return getRollbackSignal(documentId)[0]();
}

export function requestRollbackApproval(documentId: string, message: string): Promise<void> {
  getRollbackSignal(documentId)[1](message);
  return new Promise<void>((resolve) => {
    const state = documentStates.get(documentId);
    if (state) {
      state._rollbackResolvers.push(resolve);
    } else {
      resolve();
    }
  });
}

export function approveRollback(documentId: string): void {
  getRollbackSignal(documentId)[1](null);
  const state = documentStates.get(documentId);
  if (!state || state._rollbackResolvers.length === 0) return;
  for (const resolve of state._rollbackResolvers) resolve();
  state._rollbackResolvers = [];
}

export function getDocumentAwareness(documentId: string): Awareness | null {
  return getAwarenessSignal(documentId)[0]();
}

export function notifyAwarenessReady(documentId: string): void {
  const state = documentStates.get(documentId);
  if (state?.awareness) {
    getAwarenessSignal(documentId)[1](state.awareness);
  }
}
