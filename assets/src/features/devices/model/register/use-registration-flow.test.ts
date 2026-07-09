import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const oauthMnemonic =
  "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray";

const mocks = vi.hoisted(() => ({
  authApiMe: vi.fn(),
  completeOAuthFirstDeviceBootstrap: vi.fn(),
  locationState: {} as Record<string, unknown>,
  navigate: vi.fn(),
  prepareNormalRegistration: vi.fn(),
  setAuthState: undefined as undefined | ((value: unknown) => void),
  setCryptoWorkerReady: undefined as undefined | ((value: boolean) => void),
  setDeviceState: undefined as undefined | ((value: unknown) => void),
}));

vi.mock("@solidjs/router", () => ({
  useLocation: () => ({ state: mocks.locationState }),
  useNavigate: () => mocks.navigate,
}));

vi.mock("@/entities/session", async () => {
  const { createSignal } = await import("solid-js");
  const [authState, setAuthState] = createSignal<unknown>(null);
  const [deviceState, setDeviceState] = createSignal<unknown>(null);
  const [cryptoWorkerReady, setCryptoWorkerReady] = createSignal(false);
  mocks.setAuthState = setAuthState;
  mocks.setDeviceState = setDeviceState;
  mocks.setCryptoWorkerReady = setCryptoWorkerReady;
  return {
    authState,
    cryptoWorkerReady,
    deviceState,
    returnToLogin: vi.fn(async () => undefined),
  };
});

vi.mock("@/shared/api", () => ({
  authApi: {
    me: mocks.authApiMe,
  },
}));

vi.mock("../../lib/register/normal", () => ({
  prepareNormalRegistration: mocks.prepareNormalRegistration,
}));

vi.mock("../../lib/register/oauth-first-device", () => ({
  completeOAuthFirstDeviceBootstrap: mocks.completeOAuthFirstDeviceBootstrap,
}));

import { useDeviceRegistrationFlow } from "./use-registration-flow";

describe("useDeviceRegistrationFlow", () => {
  let dispose: (() => void) | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.locationState = {};
    mocks.setAuthState?.({
      user: { id: "user-oauth", email: "oauth@example.test", name: "OAuth User" },
      sessionId: "session-oauth",
      expiresAt: null,
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
      needsPasswordReentry: false,
    });
    mocks.setDeviceState?.(null);
    mocks.setCryptoWorkerReady?.(false);
    mocks.authApiMe.mockResolvedValue({ is_recovery: false });
    mocks.prepareNormalRegistration.mockResolvedValue({ kind: "oauth_first_device_required" });
    mocks.completeOAuthFirstDeviceBootstrap.mockImplementation(async () => {
      mocks.setDeviceState?.({ deviceId: "device-oauth" });
      mocks.setCryptoWorkerReady?.(true);
      return {
        dskUnavailableOAuth: false,
        recoveryMnemonic: oauthMnemonic,
        redirectPath: "/dashboard",
      };
    });
  });

  afterEach(() => {
    dispose?.();
    dispose = undefined;
  });

  it("shows the OAuth first-device recovery key instead of auto-redirecting on ready state", async () => {
    const flow = createRoot((rootDispose) => {
      dispose = rootDispose;
      return useDeviceRegistrationFlow();
    });

    await vi.waitFor(() => {
      expect(flow.oauthRecoveryMnemonic()).toBe(oauthMnemonic);
    });

    expect(flow.statusMessage()).toBe("Save your recovery key to finish setting up this account.");
    expect(mocks.navigate.mock.calls.some(([path]) => String(path).includes("/dashboard"))).toBe(
      false,
    );
  });
});
