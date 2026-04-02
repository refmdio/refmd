import { createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { resolvePostAuthRedirect } from "@/shared/lib/invite-redirect";
import {
  setFullSession,
  setAuthState,
  setDeviceState,
  setTofuErrors,
  setCryptoWorkerReady,
} from "@/entities/session";
import { login } from "@/features/auth/lib/login";
import { AuthError } from "@/features/auth/lib/auth-error";

export function useLoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [rememberMe, setRememberMe] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const result = await login(email(), password(), rememberMe());

      if (result.type === "device_required") {
        setAuthState({
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          identitySigningPublic: null,
          identityEcdhPublic: null,
          expiresAt: null,
        });
        setDeviceState(null);
        setCryptoWorkerReady(false);
        navigate("/devices/register");
        return;
      }

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

      if (result.tofuWarnings.length > 0) {
        setTofuErrors(result.tofuWarnings);
      }

      navigate(resolvePostAuthRedirect("/dashboard"));
    } catch (err) {
      if (err instanceof AuthError && err.code === "invalid_credentials") {
        setError("Invalid email or password");
      } else {
        setError(err instanceof Error ? err.message : "Login failed");
      }
    } finally {
      setLoading(false);
    }
  };

  return {
    email,
    setEmail,
    password,
    setPassword,
    rememberMe,
    setRememberMe,
    error,
    loading,
    handleSubmit,
  };
}
