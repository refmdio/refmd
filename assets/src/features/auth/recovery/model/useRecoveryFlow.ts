import { createSignal, type Accessor } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import { authState, setAuthState, setDeviceState, setCryptoWorkerReady } from "@/entities/session";
import { authApi } from "@/shared/api";
import { parseRecoveryKeyFile } from "@/shared/lib/recovery-key-format";
import { base64UrlEncode, base64UrlDecode, randomBytes } from "@/shared/lib/crypto/encoding";
import { TARGET_KDF_PARAMS } from "@/shared/lib/crypto/kdf";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

type RecoveryPhase = "input" | "recovering" | "password_set" | "error";

const EMPTY_WORDS = (): string[] => Array(24).fill("");
const MAX_FILE_SIZE = 10 * 1024;

interface RecoveryFlowState {
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

export function useRecoveryFlow(): RecoveryFlowState {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [phase, setPhase] = createSignal<RecoveryPhase>("input");
  const [error, setError] = createSignal<string | null>(null);
  const [words, setWords] = createSignal<string[]>(EMPTY_WORDS());
  const [loading, setLoading] = createSignal(false);
  const [statusMessage, setStatusMessage] = createSignal("");
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [recoveryKeysLoaded, setRecoveryKeysLoaded] = createSignal(false);
  const [identitySigningPublic, setIdentitySigningPublic] = createSignal<Uint8Array | null>(null);
  const [identityEcdhPublic, setIdentityEcdhPublic] = createSignal<Uint8Array | null>(null);

  const isPasswordReset = () => searchParams.password_reset === "true";

  const handleWordChange = (index: number, value: string, focusWord: (index: number) => void) => {
    if (value.includes(" ") && index === 0) {
      const pasted = value.trim().toLowerCase().split(/\s+/);
      if (pasted.length === 24) {
        setWords(pasted);
        focusWord(23);
        return;
      }
    }

    const updatedWords = [...words()];
    updatedWords[index] = value.toLowerCase().trim();
    setWords(updatedWords);

    if (value && index < 23) {
      focusWord(index + 1);
    }
  };

  const handleWordKeyDown = (
    index: number,
    event: KeyboardEvent,
    focusWord: (index: number) => void,
  ) => {
    if (event.key === "ArrowRight" && index < 23) {
      focusWord(index + 1);
    } else if (event.key === "ArrowLeft" && index > 0) {
      focusWord(index - 1);
    } else if (event.key === "ArrowUp") {
      const target = index - 4;
      if (target >= 0) focusWord(target);
    } else if (event.key === "ArrowDown") {
      const target = index + 4;
      if (target < 24) focusWord(target);
    } else if (event.key === "Backspace" && !words()[index] && index > 0) {
      focusWord(index - 1);
    }
  };

  const handleFileUpload = async (event: Event) => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;

    if (file.size > MAX_FILE_SIZE) {
      setError("File is too large. Recovery key files should be less than 10KB.");
      input.value = "";
      return;
    }

    try {
      const content = await file.text();
      const result = parseRecoveryKeyFile(content);

      if ("error" in result) {
        setError(result.error);
        setWords(EMPTY_WORDS());
      } else {
        const mnemonic = result.words.join(" ");
        if (!(await getCryptoWorker().validateMnemonic(mnemonic))) {
          setError("Invalid recovery key file: contains invalid BIP39 words.");
          setWords(EMPTY_WORDS());
        } else {
          setWords(result.words);
          setError(null);
        }
      }
    } catch {
      setError("Failed to read file.");
      setWords(EMPTY_WORDS());
    }

    input.value = "";
  };

  const clear = () => {
    setWords(EMPTY_WORDS());
    setError(null);
    setPhase("input");
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
      const worker = getCryptoWorker();

      setPhase("recovering");
      setStatusMessage("Fetching recovery data...");
      const recovery = await authApi.getRecovery();

      setStatusMessage("Deriving recovery key...");
      await worker.deriveRuk(mnemonic);

      setStatusMessage("Decrypting master key...");
      try {
        await worker.unwrapUmkWithRuk({
          encrypted: base64UrlDecode(recovery.recovery_encrypted_umk!),
          nonce: base64UrlDecode(recovery.recovery_nonce!),
          userId: auth.user.id,
        });
      } catch {
        throw new Error("Invalid recovery phrase. The mnemonic does not match this account.");
      }

      setStatusMessage("Decrypting identity keys...");
      const identityPublic = await worker.importIdentityKeys({
        encryptedEcdhPrivate: base64UrlDecode(recovery.encrypted_ecdh_private!),
        ecdhPrivateNonce: base64UrlDecode(recovery.encrypted_ecdh_private_nonce!),
        encryptedSigningPrivate: base64UrlDecode(recovery.encrypted_signing_private!),
        signingPrivateNonce: base64UrlDecode(recovery.encrypted_signing_private_nonce!),
      });

      setStatusMessage("Getting recovery challenge...");
      const challengeResponse = await authApi.recoveryChallenge(auth.user.email);
      const challenge = base64UrlDecode(challengeResponse.challenge);

      setStatusMessage("Signing challenge...");
      const timestampMs = Date.now();
      const emailBytes = new TextEncoder().encode(auth.user.email.toLowerCase());
      const timestampBytes = new Uint8Array(8);
      new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestampMs), true);

      const prefix = new TextEncoder().encode("recovery-session:");
      const message = new Uint8Array(
        prefix.length + challenge.length + emailBytes.length + timestampBytes.length,
      );
      message.set(prefix, 0);
      message.set(challenge, prefix.length);
      message.set(emailBytes, prefix.length + challenge.length);
      message.set(timestampBytes, prefix.length + challenge.length + emailBytes.length);

      const { signature } = await worker.signRecoveryChallenge(message);

      setStatusMessage("Creating session...");
      const sessionResponse = await authApi.recoverySession({
        email: auth.user.email,
        challenge: challengeResponse.challenge,
        signature: base64UrlEncode(signature),
        timestamp: timestampMs,
      });

      if (isPasswordReset()) {
        setRecoveryKeysLoaded(true);
        setIdentitySigningPublic(identityPublic.identitySigningPublic);
        setIdentityEcdhPublic(identityPublic.identityEcdhPublic);
        setPhase("password_set");
        setLoading(false);
        return;
      }

      setAuthState({
        user: auth.user,
        sessionId: sessionResponse.session_id,
        identitySigningPublic: identityPublic.identitySigningPublic,
        identityEcdhPublic: identityPublic.identityEcdhPublic,
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
      const worker = getCryptoWorker();
      const salt = randomBytes(16);
      const saltBase64 = base64UrlEncode(salt);
      const { authKey } = await worker.deriveAuthKeys({
        password: newPassword(),
        salt,
        kdfParams: TARGET_KDF_PARAMS,
      });

      const umkWrapped = await worker.wrapUmkForServer(auth.user.id);
      const response = await authApi.passwordSet({
        new_auth_key: base64UrlEncode(authKey),
        new_salt: saltBase64,
        new_encrypted_umk: base64UrlEncode(umkWrapped.encrypted),
        new_umk_nonce: base64UrlEncode(umkWrapped.nonce),
      });

      setAuthState({
        user: auth.user,
        sessionId: response.session_id,
        identitySigningPublic: identitySigningPublic(),
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
    submitRecovery,
    submitPasswordSet,
  };
}
