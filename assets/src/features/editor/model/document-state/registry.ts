import { createSignal } from "solid-js";
import type { Awareness } from "y-protocols/awareness";
import type { DocumentState } from "./types";

export const documentStates = new Map<string, DocumentState>();
export const documentStateEvictionDelayMs = 200;

export const errorSignals = new Map<string, ReturnType<typeof createSignal<string | null>>>();
export const reauthSignals = new Map<string, ReturnType<typeof createSignal<boolean>>>();
export const rollbackSignals = new Map<string, ReturnType<typeof createSignal<string | null>>>();
export const awarenessSignals = new Map<
  string,
  ReturnType<typeof createSignal<Awareness | null>>
>();
