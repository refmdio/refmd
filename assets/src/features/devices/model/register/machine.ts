import type { DeviceRegistrationPhase, DeviceRegistrationPublicKeys } from "./types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

export interface DeviceRegistrationMachineState {
  phase: DeviceRegistrationPhase;
  error: string | null;
  devicePublicKeys: DeviceRegistrationPublicKeys | null;
  clientNonce: Uint8Array | null;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  dskUnavailableOAuth: boolean;
  statusMessage: string;
  isRecoveryMode: boolean;
  pendingKeysGenerated: boolean;
  postApprovalPersistence: boolean;
  passwordReentryPassword: string;
  passwordReentryLoading: boolean;
  passwordReentryError: string | null;
  reauthPassword: string;
  reauthLoading: boolean;
  reauthError: string | null;
  reauthPendingPublicKeys: DeviceRegistrationPublicKeys | null;
}

export type DeviceRegistrationMachineEvent =
  | {
      type: "mode_resolved";
      isRecoveryMode: boolean;
    }
  | {
      type: "normal_registration_prepared";
      identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
      publicKeys: DeviceRegistrationPublicKeys;
      needsPassword: boolean;
      dskUnavailableOAuth: boolean;
    }
  | {
      type: "approval_waiting";
      clientNonce: Uint8Array;
    }
  | {
      type: "approval_reauth_required";
      clientNonce: Uint8Array;
      publicKeys: DeviceRegistrationPublicKeys;
    }
  | {
      type: "approval_expired";
    }
  | {
      type: "approval_rejected";
    }
  | {
      type: "recovery_progress";
      phase: Extract<DeviceRegistrationPhase, "generating" | "restoring">;
      message: string;
    }
  | {
      type: "recovery_status_updated";
      message: string;
    }
  | {
      type: "recovery_needs_password";
      publicKeys: DeviceRegistrationPublicKeys;
    }
  | {
      type: "recovery_completed";
      statusMessage: string;
      dskUnavailableOAuth: boolean;
    }
  | {
      type: "password_reentry_submitted";
    }
  | {
      type: "password_reentry_failed";
      message: string;
    }
  | {
      type: "password_reentry_resumed";
    }
  | {
      type: "password_reentry_completed";
    }
  | {
      type: "reauth_submitted";
    }
  | {
      type: "reauth_failed";
      message: string;
    }
  | {
      type: "reauth_resolved";
    }
  | {
      type: "approved_restoration_started";
    }
  | {
      type: "approved_needs_password";
    }
  | {
      type: "approved_completed";
      dskUnavailableOAuth: boolean;
    }
  | {
      type: "flow_failed";
      message: string;
    };

export function createInitialDeviceRegistrationMachineState(): DeviceRegistrationMachineState {
  return {
    phase: "generating",
    error: null,
    devicePublicKeys: null,
    clientNonce: null,
    identityHybridSigningPublicKeyMaterial: null,
    dskUnavailableOAuth: false,
    statusMessage: "",
    isRecoveryMode: false,
    pendingKeysGenerated: false,
    postApprovalPersistence: false,
    passwordReentryPassword: "",
    passwordReentryLoading: false,
    passwordReentryError: null,
    reauthPassword: "",
    reauthLoading: false,
    reauthError: null,
    reauthPendingPublicKeys: null,
  };
}

export function transitionDeviceRegistrationState(
  state: DeviceRegistrationMachineState,
  event: DeviceRegistrationMachineEvent,
): DeviceRegistrationMachineState {
  switch (event.type) {
    case "mode_resolved":
      return {
        ...state,
        isRecoveryMode: event.isRecoveryMode,
      };

    case "normal_registration_prepared":
      return {
        ...state,
        identityHybridSigningPublicKeyMaterial: event.identityHybridSigningPublicKeyMaterial,
        devicePublicKeys: event.publicKeys,
        dskUnavailableOAuth: event.needsPassword ? false : event.dskUnavailableOAuth,
        pendingKeysGenerated: event.needsPassword,
        postApprovalPersistence: false,
        phase: event.needsPassword ? "needs_password" : state.phase,
        passwordReentryError: null,
      };

    case "approval_waiting":
      return {
        ...state,
        clientNonce: event.clientNonce,
        phase: "waiting",
        error: null,
        reauthLoading: false,
        reauthError: null,
        reauthPendingPublicKeys: null,
      };

    case "approval_reauth_required":
      return {
        ...state,
        clientNonce: event.clientNonce,
        phase: "reauth",
        error: null,
        reauthLoading: false,
        reauthError: null,
        reauthPendingPublicKeys: event.publicKeys,
      };

    case "approval_expired":
      return {
        ...state,
        phase: "expired",
      };

    case "approval_rejected":
      return {
        ...state,
        phase: "error",
        error: "Device registration was rejected by an existing device.",
      };

    case "recovery_progress":
      return {
        ...state,
        phase: event.phase,
        statusMessage: event.message,
        error: null,
      };

    case "recovery_status_updated":
      return {
        ...state,
        statusMessage: event.message,
      };

    case "recovery_needs_password":
      return {
        ...state,
        devicePublicKeys: event.publicKeys,
        pendingKeysGenerated: true,
        postApprovalPersistence: true,
        phase: "needs_password",
        passwordReentryError: null,
      };

    case "recovery_completed":
      return {
        ...state,
        dskUnavailableOAuth: event.dskUnavailableOAuth,
        phase: "done",
        statusMessage: event.statusMessage,
      };

    case "password_reentry_submitted":
      return {
        ...state,
        passwordReentryLoading: true,
        passwordReentryError: null,
      };

    case "password_reentry_failed":
      return {
        ...state,
        passwordReentryLoading: false,
        passwordReentryError: event.message,
      };

    case "password_reentry_resumed":
      return {
        ...state,
        passwordReentryLoading: false,
        pendingKeysGenerated: false,
        passwordReentryError: null,
      };

    case "password_reentry_completed":
      return {
        ...state,
        phase: "done",
        passwordReentryLoading: false,
        passwordReentryError: null,
        pendingKeysGenerated: false,
        postApprovalPersistence: false,
      };

    case "reauth_submitted":
      return {
        ...state,
        reauthLoading: true,
        reauthError: null,
      };

    case "reauth_failed":
      return {
        ...state,
        reauthLoading: false,
        reauthError: event.message,
      };

    case "reauth_resolved":
      return {
        ...state,
        reauthLoading: false,
        reauthError: null,
        reauthPendingPublicKeys: null,
      };

    case "approved_restoration_started":
      return {
        ...state,
        phase: "restoring",
        error: null,
      };

    case "approved_needs_password":
      return {
        ...state,
        pendingKeysGenerated: true,
        postApprovalPersistence: true,
        phase: "needs_password",
        passwordReentryError: null,
      };

    case "approved_completed":
      return {
        ...state,
        dskUnavailableOAuth: event.dskUnavailableOAuth,
        phase: "done",
      };

    case "flow_failed":
      return {
        ...state,
        phase: "error",
        error: event.message,
      };
  }
}
