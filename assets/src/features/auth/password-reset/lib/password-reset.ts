import { authApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { getCryptoWorker, terminateCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface PasswordResetSessionData {
  user: AuthState["user"];
  sessionId: string;
}

export async function verifyPasswordResetToken(token: string): Promise<PasswordResetSessionData> {
  const data = await authApi.passwordResetVerify(token);

  try {
    await getCryptoWorker().lock();
  } catch {
    // Worker may not be initialized.
  }
  terminateCryptoWorker();

  return {
    user: data.user,
    sessionId: data.session_id,
  };
}

export async function requestPasswordReset(email: string): Promise<void> {
  await authApi.passwordResetRequest(email.trim().toLowerCase());
}
