import type { AuthState } from "@/entities/session";
import { authApi } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

interface RecoveryAttemptParams {
  auth: AuthState;
  mnemonic: string;
  isPasswordReset: boolean;
  setStatusMessage: (message: string) => void;
}

type RecoveryAttemptResult =
  | {
      kind: "password_set";
      identitySigningPublic: Uint8Array | null;
      identityEcdhPublic: Uint8Array | null;
    }
  | {
      kind: "device_registration";
      sessionId: string;
      identitySigningPublic: Uint8Array | null;
      identityEcdhPublic: Uint8Array | null;
    };

export async function recoverAccount(
  params: RecoveryAttemptParams,
): Promise<RecoveryAttemptResult> {
  const worker = getCryptoWorker();

  params.setStatusMessage("Fetching recovery data...");
  const recovery = await authApi.getRecovery();

  params.setStatusMessage("Deriving recovery key...");
  await worker.deriveRuk(params.mnemonic);

  params.setStatusMessage("Decrypting master key...");
  try {
    await worker.unwrapUmkWithRuk({
      encrypted: base64UrlDecode(recovery.recovery_encrypted_umk!),
      nonce: base64UrlDecode(recovery.recovery_nonce!),
      userId: params.auth.user.id,
    });
  } catch {
    throw new Error("Invalid recovery phrase. The mnemonic does not match this account.");
  }

  params.setStatusMessage("Decrypting identity keys...");
  const identityPublic = await worker.importIdentityKeys({
    encryptedEcdhPrivate: base64UrlDecode(recovery.encrypted_ecdh_private!),
    ecdhPrivateNonce: base64UrlDecode(recovery.encrypted_ecdh_private_nonce!),
    encryptedSigningPrivate: base64UrlDecode(recovery.encrypted_signing_private!),
    signingPrivateNonce: base64UrlDecode(recovery.encrypted_signing_private_nonce!),
  });

  params.setStatusMessage("Getting recovery challenge...");
  const challengeResponse = await authApi.recoveryChallenge(params.auth.user.email);
  const challenge = base64UrlDecode(challengeResponse.challenge);

  params.setStatusMessage("Signing challenge...");
  const timestampMs = Date.now();
  const emailBytes = new TextEncoder().encode(params.auth.user.email.toLowerCase());
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

  params.setStatusMessage("Creating session...");
  const sessionResponse = await authApi.recoverySession({
    email: params.auth.user.email,
    challenge: challengeResponse.challenge,
    signature: base64UrlEncode(signature),
    timestamp: timestampMs,
  });

  if (params.isPasswordReset) {
    return {
      kind: "password_set",
      identitySigningPublic: identityPublic.identitySigningPublic,
      identityEcdhPublic: identityPublic.identityEcdhPublic,
    };
  }

  return {
    kind: "device_registration",
    sessionId: sessionResponse.session_id,
    identitySigningPublic: identityPublic.identitySigningPublic,
    identityEcdhPublic: identityPublic.identityEcdhPublic,
  };
}
