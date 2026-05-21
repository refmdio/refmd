import type { Accessor } from "solid-js";

export type RecoveryPhase = "input" | "recovering" | "password_set" | "error";

export interface RecoveryFlowState {
  phase: Accessor<RecoveryPhase>;
  error: Accessor<string | null>;
  words: Accessor<string[]>;
  loading: Accessor<boolean>;
  statusMessage: Accessor<string>;
  isPasswordReset: Accessor<boolean>;
  newPassword: Accessor<string>;
  confirmPassword: Accessor<string>;
  recoveryKeysLoaded: Accessor<boolean>;
  setNewPassword: (value: string) => void;
  setConfirmPassword: (value: string) => void;
  handleWordChange: (index: number, value: string, focusWord: (index: number) => void) => void;
  handleWordKeyDown: (
    index: number,
    event: KeyboardEvent,
    focusWord: (index: number) => void,
  ) => void;
  handleFileUpload: (event: Event) => Promise<void>;
  clear: () => void;
  resetInputError: () => void;
  submitRecovery: (event: Event) => Promise<void>;
  submitPasswordSet: (event: Event) => Promise<void>;
}
