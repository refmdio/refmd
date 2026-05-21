import type { AuthState } from "@/entities/session";
import { authApi } from "@/shared/api";
import { base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import { TARGET_KDF_PARAMS } from "@/shared/lib/crypto/kdf-params";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export async function setRecoveryPassword(auth: AuthState, newPassword: string): Promise<string> {
  const worker = getCryptoWorker();
  const salt = randomBytes(16);
  const saltBase64 = base64UrlEncode(salt);
  const { authKey } = await worker.deriveAuthKeys({
    password: newPassword,
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

  return response.session_id;
}
