import { createSignal, onMount, type Accessor } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import { setAuthState, setDeviceState, setCryptoWorkerReady } from "@/entities/session";
import {
  requestPasswordReset,
  verifyPasswordResetToken,
} from "../../lib/password-reset/password-reset";

type Phase = "request" | "sent" | "verifying" | "error";

export function usePasswordResetPage(): {
  phase: Accessor<Phase>;
  email: Accessor<string>;
  setEmail: (value: string) => void;
  error: Accessor<string | null>;
  loading: Accessor<boolean>;
  handleRequest: (e: Event) => Promise<void>;
} {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [phase, setPhase] = createSignal<Phase>(searchParams.token ? "verifying" : "request");
  const [email, setEmail] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const verifyToken = async (token: string) => {
    setPhase("verifying");
    try {
      const data = await verifyPasswordResetToken(token);

      setAuthState({
        user: data.user,
        sessionId: data.sessionId,
        identityHybridSigningPublicKeyMaterial: null,
        identityEcdhPublic: null,
        expiresAt: null,
      });
      setDeviceState(null);
      setCryptoWorkerReady(false);

      navigate("/auth/recovery?password_reset=true");
    } catch (err) {
      const isNetwork = err instanceof TypeError;
      setError(
        isNetwork
          ? "Unable to reach the server. Please check your connection and try again."
          : "Invalid or expired reset link. Please request a new one.",
      );
      setPhase("error");
    }
  };

  onMount(() => {
    const tokenParam = Array.isArray(searchParams.token)
      ? searchParams.token[0]
      : searchParams.token;
    if (tokenParam) {
      void verifyToken(tokenParam);
    }
  });

  const handleRequest = async (e: Event) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await requestPasswordReset(email());
      setPhase("sent");
    } catch {
      setError("Request failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return {
    phase,
    email,
    setEmail,
    error,
    loading,
    handleRequest,
  };
}
