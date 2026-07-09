import { createSignal, onMount } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { resolvePostAuthRedirect } from "@/shared/lib/invite/redirect";
import { setFullSession, setCryptoWorkerReady } from "@/entities/session";
import { formatRecoveryKeyFile } from "@/shared/lib/recovery/key-format";
import {
  loadOAuthProviders,
  startOAuthAuthorization,
  type OAuthProvider,
} from "../../lib/oauth/oauth";
import { register } from "../../lib/register/register";

export function useRegisterPage() {
  const navigate = useNavigate();
  const [name, setName] = createSignal("");
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [oauthLoading, setOauthLoading] = createSignal<OAuthProvider | null>(null);
  const [oauthProviders, setOauthProviders] = createSignal<OAuthProvider[]>([]);
  const [recoveryMnemonic, setRecoveryMnemonic] = createSignal<string | null>(null);
  const [mnemonicConfirmed, setMnemonicConfirmed] = createSignal(false);
  const [showMnemonic, setShowMnemonic] = createSignal(false);

  onMount(() => {
    void (async () => {
      try {
        setOauthProviders(await loadOAuthProviders());
      } catch {
        setOauthProviders([]);
      }
    })();
  });

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
          identityHybridSigningPublicKeyMaterial: result.identityHybridSigningPublicKeyMaterial,
          identityEcdhPublic: result.identityEcdhPublic,
          expiresAt: null,
        },
        {
          deviceId: result.deviceId,
          deviceSigningKeyId: result.deviceSigningKeyId,
          deviceKeyCheckpointSequence: result.deviceKeyCheckpointSequence,
          deviceKeyCheckpointHash: result.deviceKeyCheckpointHash,
          deviceHybridSigningPublicKeyMaterial: result.deviceHybridSigningPublicKeyMaterial,
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

  const handleOAuthStart = async (provider: OAuthProvider) => {
    setError(null);
    setOauthLoading(provider);

    try {
      await startOAuthAuthorization(provider, resolvePostAuthRedirect("/dashboard"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "OAuth sign up failed");
      setOauthLoading(null);
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
    oauthLoading,
    oauthProviders,
    recoveryMnemonic,
    mnemonicConfirmed,
    showMnemonic,
    setShowMnemonic,
    handleSubmit,
    handleOAuthStart,
    handleCopyRecoveryKey,
    handleDownloadRecoveryKey,
    handleConfirmMnemonic,
  };
}
