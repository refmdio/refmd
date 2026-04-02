import { createSignal, onMount, onCleanup, type Accessor } from "solid-js";
import { useNavigate, useLocation } from "@solidjs/router";
import { authState } from "@/entities/session";
import { authApi } from "@/shared/api";
import { resolvePostAuthRedirect } from "@/shared/lib/invite-redirect";
import { completeApprovedRegistration } from "../lib/approved-registration";
import { prepareNormalRegistration } from "../lib/normal-registration";
import {
  createInitialDeviceRegistrationMachineState,
  transitionDeviceRegistrationState,
  type DeviceRegistrationMachineEvent,
  type DeviceRegistrationMachineState,
} from "./registration-machine";
import {
  clearTransientKeysBestEffort,
  completePasswordReentry,
  verifyRegistrationReauth,
} from "../lib/password-reentry";
import { startRegistrationApproval } from "../lib/registration-approval";
import { registerRecoveredDevice } from "../lib/recovery-registration";
import type { DeviceRegistrationPhase, DeviceRegistrationPublicKeys } from "./types";
interface DeviceRegistrationFlowState {
  phase: Accessor<DeviceRegistrationPhase>;
  error: Accessor<string | null>;
  devicePublicKeys: Accessor<DeviceRegistrationPublicKeys | null>;
  clientNonce: Accessor<Uint8Array | null>;
  identitySigningPublic: Accessor<Uint8Array | null>;
  dskUnavailableOAuth: Accessor<boolean>;
  pdkPassword: Accessor<string>;
  pdkLoading: Accessor<boolean>;
  pdkError: Accessor<string | null>;
  statusMessage: Accessor<string>;
  isRecoveryMode: Accessor<boolean>;
  reauthPassword: Accessor<string>;
  reauthLoading: Accessor<boolean>;
  reauthError: Accessor<string | null>;
  setPdkPassword: (value: string) => void;
  setReauthPassword: (value: string) => void;
  submitPdkReentry: (event: Event) => Promise<void>;
  submitReauth: (event: Event) => Promise<void>;
  backToLogin: () => void;
  reloadPage: () => void;
}
export function useDeviceRegistrationFlow(): DeviceRegistrationFlowState {
  const navigate = useNavigate();
  const location = useLocation();
  const isRecoveryFromState = () => (location.state as Record<string, unknown>)?.recovery === true;
  const [machine, setMachine] = createSignal(createInitialDeviceRegistrationMachineState());
  let disposeRegistrationWaiter: (() => void) | undefined;
  let redirectTimer: ReturnType<typeof setTimeout> | undefined;
  const phase = () => machine().phase;
  const error = () => machine().error;
  const devicePublicKeys = () => machine().devicePublicKeys;
  const clientNonce = () => machine().clientNonce;
  const identitySigningPublic = () => machine().identitySigningPublic;
  const dskUnavailableOAuth = () => machine().dskUnavailableOAuth;
  const pdkPassword = () => machine().pdkPassword;
  const pdkLoading = () => machine().pdkLoading;
  const pdkError = () => machine().pdkError;
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
    if (disposeRegistrationWaiter) disposeRegistrationWaiter();
    if (redirectTimer) clearTimeout(redirectTimer);
  });
  onMount(async () => {
    const auth = authState();
    if (!auth) {
      navigate("/auth/login");
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
      identitySigningPublic: prepared.identitySigningPublic,
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
    const result = await startRegistrationApproval({
      publicKeys,
      identitySigningPublic: identitySigningPublic()!,
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
  const submitPdkReentry = async (event: Event) => {
    event.preventDefault();
    applyEvent({
      type: "password_reentry_submitted",
    });
    try {
      const auth = authState();
      if (!auth) throw new Error("No session");
      const outcome = await completePasswordReentry({
        auth,
        password: pdkPassword(),
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
  return {
    phase,
    error,
    devicePublicKeys,
    clientNonce,
    identitySigningPublic,
    dskUnavailableOAuth,
    pdkPassword,
    pdkLoading,
    pdkError,
    statusMessage,
    isRecoveryMode,
    reauthPassword,
    reauthLoading,
    reauthError,
    setPdkPassword: (value) => patchMachine({ pdkPassword: value }),
    setReauthPassword: (value) => patchMachine({ reauthPassword: value }),
    submitPdkReentry,
    submitReauth,
    backToLogin: () => navigate("/auth/login"),
    reloadPage: () => window.location.reload(),
  };
}
function resolveCompletionRedirectPath(fallbackPath: string): string {
  return resolvePostAuthRedirect(fallbackPath);
}
