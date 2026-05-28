import { createEffect, createSignal, onMount, onCleanup, type Accessor } from "solid-js";
import { useNavigate, useLocation } from "@solidjs/router";
import { authState, cryptoWorkerReady, deviceState, returnToLogin } from "@/entities/session";
import { authApi } from "@/shared/api";
import { resolvePostAuthRedirect } from "@/shared/lib/invite/redirect";
import { completeApprovedRegistration } from "../../lib/register/approval-complete";
import { prepareNormalRegistration } from "../../lib/register/normal";
import {
  createInitialDeviceRegistrationMachineState,
  transitionDeviceRegistrationState,
  type DeviceRegistrationMachineEvent,
  type DeviceRegistrationMachineState,
} from "./machine";
import {
  clearTransientKeysBestEffort,
  completePasswordReentry,
  verifyRegistrationReauth,
} from "../../lib/register/session-password";
import { startRegistrationApproval } from "../../lib/register/approval-start";
import { registerRecoveredDevice } from "../../lib/register/recovery";
import type { DeviceRegistrationPhase, DeviceRegistrationPublicKeys } from "./types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
interface DeviceRegistrationFlowState {
  phase: Accessor<DeviceRegistrationPhase>;
  error: Accessor<string | null>;
  devicePublicKeys: Accessor<DeviceRegistrationPublicKeys | null>;
  clientNonce: Accessor<Uint8Array | null>;
  identityHybridSigningPublicKeyMaterial: Accessor<HybridSigningPublicKeyMaterial | null>;
  dskUnavailableOAuth: Accessor<boolean>;
  passwordReentryPassword: Accessor<string>;
  passwordReentryLoading: Accessor<boolean>;
  passwordReentryError: Accessor<string | null>;
  statusMessage: Accessor<string>;
  isRecoveryMode: Accessor<boolean>;
  reauthPassword: Accessor<string>;
  reauthLoading: Accessor<boolean>;
  reauthError: Accessor<string | null>;
  setPasswordReentryPassword: (value: string) => void;
  setReauthPassword: (value: string) => void;
  submitPasswordReentry: (event: Event) => Promise<void>;
  submitReauth: (event: Event) => Promise<void>;
  openRecovery: (event: MouseEvent) => void;
  backToLogin: () => void;
  reloadPage: () => void;
}
export function useDeviceRegistrationFlow(): DeviceRegistrationFlowState {
  const navigate = useNavigate();
  const location = useLocation();
  const isRecoveryFromState = () => (location.state as Record<string, unknown>)?.recovery === true;
  const [machine, setMachine] = createSignal(createInitialDeviceRegistrationMachineState());
  let disposeRegistrationWaiter: (() => void) | undefined;
  let registrationAbortController: AbortController | undefined;
  let redirectTimer: ReturnType<typeof setTimeout> | undefined;
  const phase = () => machine().phase;
  const error = () => machine().error;
  const devicePublicKeys = () => machine().devicePublicKeys;
  const clientNonce = () => machine().clientNonce;
  const identityHybridSigningPublicKeyMaterial = () =>
    machine().identityHybridSigningPublicKeyMaterial;
  const dskUnavailableOAuth = () => machine().dskUnavailableOAuth;
  const passwordReentryPassword = () => machine().passwordReentryPassword;
  const passwordReentryLoading = () => machine().passwordReentryLoading;
  const passwordReentryError = () => machine().passwordReentryError;
  const statusMessage = () => machine().statusMessage;
  const isRecoveryMode = () => machine().isRecoveryMode;
  const reauthPassword = () => machine().reauthPassword;
  const reauthLoading = () => machine().reauthLoading;
  const reauthError = () => machine().reauthError;
  const pendingKeysGenerated = () => machine().pendingKeysGenerated;
  const postApprovalPersistence = () => machine().postApprovalPersistence;
  const reauthPendingPublicKeys = () => machine().reauthPendingPublicKeys;
  const applyEvent = (event: DeviceRegistrationMachineEvent) => {
    setMachine((current) => transitionDeviceRegistrationState(current, event));
  };
  const patchMachine = (patch: Partial<DeviceRegistrationMachineState>) => {
    setMachine((current) => ({
      ...current,
      ...patch,
    }));
  };
  onCleanup(() => {
    registrationAbortController?.abort();
    if (disposeRegistrationWaiter) disposeRegistrationWaiter();
    if (redirectTimer) clearTimeout(redirectTimer);
  });
  createEffect(() => {
    const auth = authState();
    if (!auth) return;
    if (auth.needsPasswordReentry || (deviceState()?.deviceId && cryptoWorkerReady())) {
      navigate(resolvePostAuthRedirect("/dashboard"), { replace: true });
    }
  });
  onMount(async () => {
    const auth = authState();
    if (!auth) {
      navigate("/auth/login");
      return;
    }
    if (auth.needsPasswordReentry || (deviceState()?.deviceId && cryptoWorkerReady())) {
      navigate(resolvePostAuthRedirect("/dashboard"), { replace: true });
      return;
    }
    try {
      let isRecovery = isRecoveryFromState();
      if (!isRecovery) {
        const me = await authApi.me();
        isRecovery = me.is_recovery === true;
      }
      applyEvent({
        type: "mode_resolved",
        isRecoveryMode: isRecovery,
      });
      if (isRecovery) {
        await startRecoveryRegistration(auth);
      } else {
        await startNormalRegistration(auth);
      }
    } catch (setupError) {
      if (setupError instanceof Error && setupError.name === "AbortError") return;
      applyEvent({
        type: "flow_failed",
        message: setupError instanceof Error ? setupError.message : "Setup failed",
      });
    }
  });
  const startNormalRegistration = async (auth: NonNullable<ReturnType<typeof authState>>) => {
    const prepared = await prepareNormalRegistration(auth.user.id);
    applyEvent({
      type: "normal_registration_prepared",
      identityHybridSigningPublicKeyMaterial: prepared.identityHybridSigningPublicKeyMaterial,
      publicKeys: prepared.publicKeys,
      needsPassword: prepared.decision.kind === "needs_password",
      dskUnavailableOAuth:
        prepared.decision.kind === "ready" ? prepared.decision.dskUnavailableOAuth : false,
    });
    if (prepared.decision.kind === "needs_password") {
      return;
    }
    await createRegistrationAndWait(prepared.publicKeys);
  };
  const createRegistrationAndWait = async (publicKeys: DeviceRegistrationPublicKeys) => {
    registrationAbortController?.abort();
    const abortController = new AbortController();
    registrationAbortController = abortController;
    const result = await startRegistrationApproval({
      publicKeys,
      identityHybridSigningPublicKeyMaterial: identityHybridSigningPublicKeyMaterial()!,
      signal: abortController.signal,
      shouldKeepWaiting: () => phase() === "waiting",
      onReauthRequired: () => {},
      onApproved: async (deviceId) => {
        disposeRegistrationWaiter = undefined;
        await handleApproved(deviceId, publicKeys);
      },
      onExpired: () => {
        disposeRegistrationWaiter = undefined;
        applyEvent({
          type: "approval_expired",
        });
      },
      onRejected: () => {
        disposeRegistrationWaiter = undefined;
        applyEvent({
          type: "approval_rejected",
        });
      },
    });
    if (registrationAbortController === abortController) {
      registrationAbortController = undefined;
    }
    if (result.status === "reauth_required") {
      applyEvent({
        type: "approval_reauth_required",
        clientNonce: result.clientNonce,
        publicKeys,
      });
      return;
    }
    applyEvent({
      type: "approval_waiting",
      clientNonce: result.clientNonce,
    });
    disposeRegistrationWaiter = result.dispose;
  };
  const openRecovery = (event: MouseEvent) => {
    event.preventDefault();
    registrationAbortController?.abort();
    registrationAbortController = undefined;
    if (disposeRegistrationWaiter) {
      disposeRegistrationWaiter();
      disposeRegistrationWaiter = undefined;
    }
    navigate("/auth/recovery");
  };
  const startRecoveryRegistration = async (auth: NonNullable<ReturnType<typeof authState>>) => {
    applyEvent({
      type: "recovery_progress",
      phase: "generating",
      message: "Generating device keys...",
    });
    applyEvent({
      type: "recovery_progress",
      phase: "restoring",
      message: "Registering device...",
    });
    const result = await registerRecoveredDevice({
      auth,
      completionRedirectPath: resolveCompletionRedirectPath("/"),
      onStatusMessage: (message) =>
        applyEvent({
          type: "recovery_status_updated",
          message,
        }),
    });
    if (result.kind === "navigate") {
      navigate(result.path);
      return;
    }
    if (result.kind === "needs_password") {
      applyEvent({
        type: "recovery_needs_password",
        publicKeys: result.publicKeys,
      });
      return;
    }
    applyEvent({
      type: "recovery_completed",
      statusMessage: result.statusMessage,
      dskUnavailableOAuth: result.dskUnavailableOAuth,
    });
    redirectTimer = setTimeout(() => navigate(result.redirectPath), 3000);
  };
  const submitPasswordReentry = async (event: Event) => {
    event.preventDefault();
    applyEvent({
      type: "password_reentry_submitted",
    });
    try {
      const auth = authState();
      if (!auth) throw new Error("No session");
      const outcome = await completePasswordReentry({
        auth,
        password: passwordReentryPassword(),
        pendingKeysGenerated: pendingKeysGenerated(),
        devicePublicKeys: devicePublicKeys(),
        postApprovalPersistence: postApprovalPersistence(),
        completionRedirectPath: resolveCompletionRedirectPath("/dashboard"),
      });
      if (outcome.kind === "complete") {
        applyEvent({
          type: "password_reentry_completed",
        });
        navigate(outcome.redirectPath);
        return;
      }
      applyEvent({
        type: "password_reentry_resumed",
      });
      await createRegistrationAndWait(outcome.publicKeys);
    } catch (reentryError) {
      applyEvent({
        type: "password_reentry_failed",
        message:
          reentryError instanceof Error ? reentryError.message : "Password verification failed",
      });
      await clearTransientKeysBestEffort();
    }
  };
  const submitReauth = async (event: Event) => {
    event.preventDefault();
    applyEvent({
      type: "reauth_submitted",
    });
    try {
      const auth = authState();
      if (!auth) throw new Error("No session");
      const publicKeys = await verifyRegistrationReauth(
        auth,
        reauthPassword(),
        reauthPendingPublicKeys(),
      );
      applyEvent({
        type: "reauth_resolved",
      });
      await createRegistrationAndWait(publicKeys);
    } catch (reauthErrorValue) {
      applyEvent({
        type: "reauth_failed",
        message:
          reauthErrorValue instanceof Error
            ? reauthErrorValue.message
            : "Password verification failed",
      });
      await clearTransientKeysBestEffort();
    }
  };
  const handleApproved = async (deviceId: string, publicKeys: DeviceRegistrationPublicKeys) => {
    const auth = authState();
    if (!auth) {
      applyEvent({ type: "flow_failed", message: "Session expired. Please log in again." });
      return;
    }
    applyEvent({
      type: "approved_restoration_started",
    });
    try {
      const result = await completeApprovedRegistration({
        auth,
        deviceId,
        publicKeys,
        completionRedirectPath: resolveCompletionRedirectPath("/dashboard"),
      });
      if (result.kind === "needs_password") {
        applyEvent({
          type: "approved_needs_password",
        });
        return;
      }
      applyEvent({
        type: "approved_completed",
        dskUnavailableOAuth: result.dskUnavailableOAuth,
      });
      navigate(result.redirectPath);
    } catch (approvalError) {
      applyEvent({
        type: "flow_failed",
        message: approvalError instanceof Error ? approvalError.message : "Key restoration failed",
      });
    }
  };
  const backToLogin = () => {
    void returnToLogin();
  };
  return {
    phase,
    error,
    devicePublicKeys,
    clientNonce,
    identityHybridSigningPublicKeyMaterial,
    dskUnavailableOAuth,
    passwordReentryPassword,
    passwordReentryLoading,
    passwordReentryError,
    statusMessage,
    isRecoveryMode,
    reauthPassword,
    reauthLoading,
    reauthError,
    setPasswordReentryPassword: (value) => patchMachine({ passwordReentryPassword: value }),
    setReauthPassword: (value) => patchMachine({ reauthPassword: value }),
    submitPasswordReentry,
    submitReauth,
    openRecovery,
    backToLogin,
    reloadPage: () => window.location.reload(),
  };
}
function resolveCompletionRedirectPath(fallbackPath: string): string {
  return resolvePostAuthRedirect(fallbackPath);
}
