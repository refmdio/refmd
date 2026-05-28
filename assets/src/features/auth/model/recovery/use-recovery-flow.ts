import { createSignal } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import {
  authState,
  returnToLogin,
  setAuthState,
  setDeviceState,
  setCryptoWorkerReady,
} from "@/entities/session";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { recoverAccount } from "../../lib/recovery/recover";
import { setRecoveryPassword } from "../../lib/recovery/password-set";
import {
  applyWordChange,
  createEmptyWords,
  getWordFocusTarget,
  readWordsFromFile,
} from "./mnemonic";
import type { RecoveryFlowState, RecoveryPhase } from "./types";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

export function useRecoveryFlow(): RecoveryFlowState {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [phase, setPhase] = createSignal<RecoveryPhase>("input");
  const [error, setError] = createSignal<string | null>(null);
  const [words, setWords] = createSignal<string[]>(createEmptyWords());
  const [loading, setLoading] = createSignal(false);
  const [statusMessage, setStatusMessage] = createSignal("");
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [recoveryKeysLoaded, setRecoveryKeysLoaded] = createSignal(false);
  const [identityHybridSigningPublicKeyMaterial, setIdentitySigningPublic] =
    createSignal<HybridSigningPublicKeyMaterial | null>(null);
  const [identityEcdhPublic, setIdentityEcdhPublic] = createSignal<Uint8Array | null>(null);

  const isPasswordReset = () => searchParams.password_reset === "true";

  const handleWordChange = (index: number, value: string, focusWord: (index: number) => void) => {
    const next = applyWordChange(words(), index, value);
    setWords(next.words);
    if (next.focusIndex !== null) {
      focusWord(next.focusIndex);
    }
  };

  const handleWordKeyDown = (
    index: number,
    event: KeyboardEvent,
    focusWord: (index: number) => void,
  ) => {
    const focusIndex = getWordFocusTarget(words(), index, event);
    if (focusIndex !== null) {
      focusWord(focusIndex);
    }
  };

  const handleFileUpload = async (event: Event) => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    const result = await readWordsFromFile(file);
    if ("error" in result) {
      setError(result.error);
      setWords(createEmptyWords());
    } else {
      setWords(result.words);
      setError(null);
    }

    input.value = "";
  };

  const clear = () => {
    setWords(createEmptyWords());
    setError(null);
    setPhase("input");
  };

  const backToLogin = () => {
    void returnToLogin();
  };

  const submitRecovery = async (event: Event) => {
    event.preventDefault();
    const auth = authState();
    if (!auth) {
      navigate("/auth/login");
      return;
    }

    const mnemonic = words().join(" ");
    if (!(await getCryptoWorker().validateMnemonic(mnemonic))) {
      setError("Invalid recovery phrase. Please check all 24 words.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      setPhase("recovering");
      const result = await recoverAccount({
        auth,
        mnemonic,
        isPasswordReset: isPasswordReset(),
        setStatusMessage,
      });

      if (result.kind === "password_set") {
        setRecoveryKeysLoaded(true);
        setIdentitySigningPublic(result.identityHybridSigningPublicKeyMaterial);
        setIdentityEcdhPublic(result.identityEcdhPublic);
        setPhase("password_set");
        setLoading(false);
        return;
      }

      setAuthState({
        user: auth.user,
        sessionId: result.sessionId,
        identityHybridSigningPublicKeyMaterial: result.identityHybridSigningPublicKeyMaterial,
        identityEcdhPublic: result.identityEcdhPublic,
        expiresAt: auth.expiresAt,
      });
      setDeviceState(null);
      setCryptoWorkerReady(false);
      navigate("/devices/register", { state: { recovery: true } });
    } catch (recoveryError) {
      setError(recoveryError instanceof Error ? recoveryError.message : "Recovery failed");
      setPhase("error");
    } finally {
      setLoading(false);
    }
  };

  const submitPasswordSet = async (event: Event) => {
    event.preventDefault();
    const auth = authState();
    if (!auth || !recoveryKeysLoaded()) {
      navigate("/auth/login");
      return;
    }

    if (newPassword() !== confirmPassword()) {
      setError("Passwords do not match");
      return;
    }

    if (newPassword().length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const sessionId = await setRecoveryPassword(auth, newPassword());

      setAuthState({
        user: auth.user,
        sessionId,
        identityHybridSigningPublicKeyMaterial: identityHybridSigningPublicKeyMaterial(),
        identityEcdhPublic: identityEcdhPublic(),
        expiresAt: auth.expiresAt,
      });
      setDeviceState(null);
      setCryptoWorkerReady(false);
      navigate("/devices/register", { state: { recovery: true } });
    } catch (passwordSetError) {
      setError(
        passwordSetError instanceof Error ? passwordSetError.message : "Password set failed",
      );
      setPhase("error");
    } finally {
      setLoading(false);
    }
  };

  return {
    phase,
    error,
    words,
    loading,
    statusMessage,
    isPasswordReset,
    newPassword,
    confirmPassword,
    recoveryKeysLoaded,
    setNewPassword,
    setConfirmPassword,
    handleWordChange,
    handleWordKeyDown,
    handleFileUpload,
    clear,
    resetInputError: () => {
      setPhase("input");
      setError(null);
    },
    backToLogin,
    submitRecovery,
    submitPasswordSet,
  };
}
