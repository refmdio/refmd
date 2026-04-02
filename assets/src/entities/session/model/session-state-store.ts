import { createRoot, createSignal, type Accessor, type Setter } from "solid-js";

interface AuthUser {
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

type SessionStateSignals = {
  authState: Accessor<AuthState | null>;
  setAuthStateRaw: Setter<AuthState | null>;
  deviceState: Accessor<DeviceState | null>;
  setDeviceStateRaw: Setter<DeviceState | null>;
  tofuErrors: Accessor<string[]>;
  setTofuErrorsRaw: Setter<string[]>;
  cryptoWorkerReady: Accessor<boolean>;
  setCryptoWorkerReadyRaw: Setter<boolean>;
};

class SessionStateStore {
  private readonly signals: SessionStateSignals;
  private readonly disposeRoot: () => void;

  constructor() {
    const { signals, disposeRoot } = createRoot<{
      signals: SessionStateSignals;
      disposeRoot: () => void;
    }>((dispose) => {
      const [authState, setAuthStateRaw] = createSignal<AuthState | null>(null);
      const [deviceState, setDeviceStateRaw] = createSignal<DeviceState | null>(null);
      const [tofuErrors, setTofuErrorsRaw] = createSignal<string[]>([]);
      const [cryptoWorkerReady, setCryptoWorkerReadyRaw] = createSignal(false);

      return {
        signals: {
          authState,
          setAuthStateRaw,
          deviceState,
          setDeviceStateRaw,
          tofuErrors,
          setTofuErrorsRaw,
          cryptoWorkerReady,
          setCryptoWorkerReadyRaw,
        },
        disposeRoot: dispose,
      };
    });

    this.signals = signals;
    this.disposeRoot = disposeRoot;
  }

  authState(): AuthState | null {
    return this.signals.authState();
  }

  deviceState(): DeviceState | null {
    return this.signals.deviceState();
  }

  tofuErrors(): string[] {
    return this.signals.tofuErrors();
  }

  cryptoWorkerReady(): boolean {
    return this.signals.cryptoWorkerReady();
  }

  getKekResolverSession() {
    return { auth: this.authState(), device: this.deviceState() };
  }

  setCryptoWorkerReady(ready: boolean): void {
    this.signals.setCryptoWorkerReadyRaw(ready);
  }

  setTofuErrors(errors: string[]): void {
    this.signals.setTofuErrorsRaw(errors);
  }

  setAuthState(state: AuthState | null): void {
    this.signals.setAuthStateRaw(state);
    if (!state) {
      this.signals.setDeviceStateRaw(null);
      this.signals.setCryptoWorkerReadyRaw(false);
    }
  }

  setDeviceState(state: DeviceState | null): void {
    this.signals.setDeviceStateRaw(state);
  }

  setFullSession(auth: AuthState, device: DeviceState): void {
    this.signals.setAuthStateRaw(auth);
    this.signals.setDeviceStateRaw(device);
  }

  clearSession(): void {
    this.signals.setAuthStateRaw(null);
    this.signals.setDeviceStateRaw(null);
    this.signals.setCryptoWorkerReadyRaw(false);
    this.signals.setTofuErrorsRaw([]);
  }

  dispose(): void {
    this.disposeRoot();
  }
}

let sessionStateStore = new SessionStateStore();

function replaceSessionStateStore(): void {
  sessionStateStore.dispose();
  sessionStateStore = new SessionStateStore();
}

export const authState = () => sessionStateStore.authState();
export const deviceState = () => sessionStateStore.deviceState();
export const tofuErrors = () => sessionStateStore.tofuErrors();
export const cryptoWorkerReady = () => sessionStateStore.cryptoWorkerReady();

export function getKekResolverSession() {
  return sessionStateStore.getKekResolverSession();
}

export function setCryptoWorkerReady(ready: boolean): void {
  sessionStateStore.setCryptoWorkerReady(ready);
}

export function setTofuErrors(errors: string[]): void {
  sessionStateStore.setTofuErrors(errors);
}

export function setAuthState(state: AuthState | null): void {
  sessionStateStore.setAuthState(state);
}

export function setDeviceState(state: DeviceState | null): void {
  sessionStateStore.setDeviceState(state);
}

export function setFullSession(auth: AuthState, device: DeviceState): void {
  sessionStateStore.setFullSession(auth, device);
}

export function clearSession(): void {
  sessionStateStore.clearSession();
}

export function resetSessionStateStoreForTests(): void {
  replaceSessionStateStore();
}
