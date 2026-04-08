import { createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { resolvePostAuthRedirect } from "@/shared/lib/invite/redirect";
import { setFullSession, setCryptoWorkerReady } from "@/entities/session";
import { formatRecoveryKeyFile } from "@/shared/lib/recovery/key-format";
import { register } from "@/features/auth/register";

export function useRegisterPage() {
  const navigate = useNavigate();
  const [name, setName] = createSignal("");
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [recoveryMnemonic, setRecoveryMnemonic] = createSignal<string | null>(null);
  const [mnemonicConfirmed, setMnemonicConfirmed] = createSignal(false);
  const [showMnemonic, setShowMnemonic] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);

    if (password().length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password() !== confirmPassword()) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      const result = await register(email(), name(), password());
      setRecoveryMnemonic(result.recoveryMnemonic);

      setFullSession(
        {
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          identitySigningPublic: result.identitySigningPublic,
          identityEcdhPublic: result.identityEcdhPublic,
          expiresAt: null,
        },
        {
          deviceId: result.deviceId,
          deviceSigningPublic: result.deviceSigningPublic,
          deviceEcdhPublic: result.deviceEcdhPublic,
        },
      );

      if (result.workerReady) {
        setCryptoWorkerReady(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  const handleCopyRecoveryKey = async () => {
    const mnemonic = recoveryMnemonic();
    if (!mnemonic) return;

    try {
      await navigator.clipboard.writeText(mnemonic);
      setMnemonicConfirmed(true);
    } catch {
      // Clipboard write may fail (permissions, insecure context).
    }
  };

  const handleDownloadRecoveryKey = () => {
    const mnemonic = recoveryMnemonic();
    if (!mnemonic) return;

    const content = formatRecoveryKeyFile(mnemonic);
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "refmd-recovery-key.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setMnemonicConfirmed(true);
  };

  const handleConfirmMnemonic = () => {
    setPassword("");
    setConfirmPassword("");
    navigate(resolvePostAuthRedirect("/dashboard"));
  };

  return {
    name,
    setName,
    email,
    setEmail,
    password,
    setPassword,
    confirmPassword,
    setConfirmPassword,
    error,
    loading,
    recoveryMnemonic,
    mnemonicConfirmed,
    showMnemonic,
    setShowMnemonic,
    handleSubmit,
    handleCopyRecoveryKey,
    handleDownloadRecoveryKey,
    handleConfirmMnemonic,
  };
}
