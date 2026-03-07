import { createSignal } from "solid-js";
import type { IdentityKeyPair } from "@/shared/lib/crypto";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
}

export interface AuthState {
  user: AuthUser;
  sessionId: string;
  umk: Uint8Array | null;
  identityKeys: IdentityKeyPair | null;
  expiresAt: string | null;
  needsPasswordReentry?: boolean;
}

export interface DeviceState {
  deviceId: string;
  deviceEcdhPrivate: Uint8Array | null;
  deviceSigningPrivate: Uint8Array | null;
}

const [authState, setAuthStateRaw] = createSignal<AuthState | null>(null);
const [deviceState, setDeviceStateRaw] = createSignal<DeviceState | null>(null);

export { authState, deviceState };

export function setAuthState(state: AuthState | null): void {
  setAuthStateRaw(state);
  if (!state) {
    setDeviceStateRaw(null);
  }
}

export function setDeviceState(state: DeviceState | null): void {
  setDeviceStateRaw(state);
}

export function setFullSession(auth: AuthState, device: DeviceState): void {
  setAuthStateRaw(auth);
  setDeviceStateRaw(device);
}

export function clearSession(): void {
  setAuthStateRaw(null);
  setDeviceStateRaw(null);
}

export function isAuthenticated(): boolean {
  const auth = authState();
  return auth !== null && auth.umk !== null && auth.identityKeys !== null;
}
