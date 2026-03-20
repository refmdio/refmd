import { createSignal } from "solid-js";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
}

export interface AuthState {
  user: AuthUser;
  sessionId: string;
  expiresAt: string | null;
  needsPasswordReentry?: boolean;
  identitySigningPublic: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
}

export interface DeviceState {
  deviceId: string;
  deviceSigningPublic: Uint8Array | null;
  deviceEcdhPublic: Uint8Array | null;
}

const [authState, setAuthStateRaw] = createSignal<AuthState | null>(null);
const [deviceState, setDeviceStateRaw] = createSignal<DeviceState | null>(null);
const [tofuErrors, setTofuErrors] = createSignal<string[]>([]);
const [cryptoWorkerReady, setCryptoWorkerReadyRaw] = createSignal(false);

export { authState, deviceState, tofuErrors, setTofuErrors, cryptoWorkerReady };

export function setCryptoWorkerReady(ready: boolean): void {
  setCryptoWorkerReadyRaw(ready);
}

export function setAuthState(state: AuthState | null): void {
  setAuthStateRaw(state);
  if (!state) {
    setDeviceStateRaw(null);
    setCryptoWorkerReadyRaw(false);
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
  setCryptoWorkerReadyRaw(false);
}

export function isAuthenticated(): boolean {
  return authState() !== null && cryptoWorkerReady();
}
