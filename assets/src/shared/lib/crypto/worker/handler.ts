import type { CryptoRequest } from "./types";
import type { WorkerKeyState } from "./state";
import {
  handleCacheDek,
  handleDecryptContent,
  handleDecryptOfflineCache,
  handleDecryptOfflinePending,
  handleDecryptTitle,
  handleDecryptTitleBatch,
  handleEncryptContent,
  handleEncryptOfflineCache,
  handleEncryptOfflinePending,
  handleEncryptTitle,
  handleEvictDek,
  handleGenerateDek,
  handleHasDek,
  handleUnwrapDek,
  handleUnwrapDekFromOffline,
  handleWrapDek,
  handleWrapDekForOffline,
} from "./handler-dek";
import {
  handleEcdhDecrypt,
  handleEcdhDecryptUmk,
  handleEcdhEncrypt,
  handleEcdhEncryptUmk,
} from "./handler-ecdh";
import {
  handleClearTransientKeys,
  handleGetDeviceId,
  handleGetPublicKeys,
  handleInit,
  handleInitFromPassword,
  handleIsReady,
  handleLock,
  handleSetDsk,
  handleSetInitialized,
  handleSetUserContext,
} from "./handler-lifecycle";
import {
  handleDeriveAuthKeys,
  handleDeriveRuk,
  handleGenerateClientNonce,
  handleGenerateDeviceKeys,
  handleGenerateDskKey,
  handleGenerateIdentityKeys,
  handleGenerateInvitationToken,
  handleGenerateRecoveryKey,
  handleGenerateUmk,
  handleImportDeviceKeys,
  handleImportIdentityKeys,
  handleImportUmk,
  handleSha256Hash,
  handleUnwrapDeviceKeysFromDsk,
  handleUnwrapUmkFromDsk,
  handleUnwrapUmkWithRuk,
  handleUnwrapWithDsk,
  handleUnwrapWithPdk,
  handleValidateMnemonic,
  handleWrapDeviceKeysWithDsk,
  handleWrapIdentityKeysForServer,
  handleWrapUmkForServer,
  handleWrapUmkWithDsk,
  handleWrapUmkWithRuk,
  handleWrapWithDsk,
  handleWrapWithPdk,
} from "./handler-keys";
import {
  handleCacheKek,
  handleDecryptKekFromDeviceEnvelope,
  handleDecryptKekFromInvitation,
  handleDecryptKekFromMemberEnvelope,
  handleEncryptKekForDevice,
  handleEncryptKekForInvitation,
  handleEncryptKekForMember,
  handleGenerateKek,
  handleResolveKek,
  handleSetActiveKekVersion,
  handleUnwrapKekFromBackup,
  handleUnwrapKekFromOffline,
  handleWrapKekForOffline,
  handleWrapKekWithUmk,
} from "./handler-kek";
import {
  handleBlake3Hash,
  handleCalculateFingerprint,
  handleComputeSas,
  handleComputeSnapshotProof,
  handleComputeUpdateHash,
  handleSignDeviceApproval,
  handleSignDeviceRegistration,
  handleSignMessage,
  handleSignPop,
  handleSignRecoveryChallenge,
  handleSignSessionProof,
  handleSignWsEnvelope,
  handleVerifyDeviceIdentitySignature,
  handleVerifyEd25519,
  handleVerifySessionProof,
  handleVerifyWsSignature,
} from "./handler-sign";
import {
  handleDecryptTrustState,
  handleEncryptTrustState,
  handleTofuGetAllEntries,
  handleTofuHandleResult,
  handleTofuImportEntries,
  handleTofuTrustDevice,
  handleTofuUpdateLastSeen,
  handleTofuVerify,
  handleTofuVerifyAllDevices,
} from "./handler-tofu";
import { withCryptoOperationError } from "./handler-utils";

export async function handleRequest(
  state: WorkerKeyState,
  request: CryptoRequest,
): Promise<unknown> {
  const p = request.payload;

  switch (request.type) {
    case "init":
      return handleInit(state, p);
    case "init-from-password":
      return handleInitFromPassword(state, p);
    case "lock":
      return handleLock(state);
    case "get-public-keys":
      return handleGetPublicKeys(state);
    case "get-device-id":
      return handleGetDeviceId(state);
    case "is-ready":
      return handleIsReady(state);
    case "set-user-context":
      return handleSetUserContext(state, p);
    case "set-dsk":
      return handleSetDsk(state, p);
    case "set-initialized":
      return handleSetInitialized(state);
    case "clear-transient-keys":
      return handleClearTransientKeys();

    case "import-identity-keys":
      return handleImportIdentityKeys(state, p);
    case "import-device-keys":
      return handleImportDeviceKeys(state, p);
    case "import-umk":
      return handleImportUmk(state, p);

    case "generate-identity-keys":
      return handleGenerateIdentityKeys(state);
    case "generate-device-keys":
      return handleGenerateDeviceKeys(state);
    case "generate-umk":
      return handleGenerateUmk(state);
    case "generate-kek":
      return handleGenerateKek(state, p);
    case "generate-dek":
      return handleGenerateDek(state, p);
    case "generate-client-nonce":
      return handleGenerateClientNonce();
    case "generate-recovery-key":
      return handleGenerateRecoveryKey(state);

    case "derive-auth-keys":
      return handleDeriveAuthKeys(p);
    case "validate-mnemonic":
      return handleValidateMnemonic(p);
    case "derive-ruk":
      return handleDeriveRuk(p);

    case "wrap-umk-for-server":
      return handleWrapUmkForServer(state, p);
    case "wrap-umk-with-ruk":
      return handleWrapUmkWithRuk(state);
    case "unwrap-umk-with-ruk":
      return withCryptoOperationError("decryption_failed", () => handleUnwrapUmkWithRuk(state, p));

    case "wrap-identity-keys-for-server":
      return handleWrapIdentityKeysForServer(state, p);

    case "wrap-dek":
      return handleWrapDek(state, p);
    case "unwrap-dek":
      return withCryptoOperationError("decryption_failed", () => handleUnwrapDek(state, p));
    case "encrypt-title":
      return handleEncryptTitle(state, p);
    case "decrypt-title":
      return withCryptoOperationError("decryption_failed", () => handleDecryptTitle(state, p));
    case "decrypt-title-batch":
      return withCryptoOperationError("decryption_failed", () => handleDecryptTitleBatch(state, p));
    case "encrypt-content":
      return handleEncryptContent(state, p);
    case "decrypt-content":
      return withCryptoOperationError("decryption_failed", () => handleDecryptContent(state, p));
    case "encrypt-snapshot":
      return handleEncryptContent(state, p);
    case "decrypt-snapshot":
      return withCryptoOperationError("decryption_failed", () => handleDecryptContent(state, p));
    case "has-dek":
      return handleHasDek(state, p);
    case "cache-dek":
      return handleCacheDek(state, p);
    case "evict-dek":
      return handleEvictDek(state, p);

    case "set-active-kek-version":
      return handleSetActiveKekVersion(state, p);
    case "resolve-kek":
      return handleResolveKek(state, p);
    case "encrypt-kek-for-device":
      return handleEncryptKekForDevice(state, p);
    case "decrypt-kek-from-device-envelope":
      return withCryptoOperationError("decryption_failed", () =>
        handleDecryptKekFromDeviceEnvelope(state, p),
      );
    case "encrypt-kek-for-member":
      return handleEncryptKekForMember(state, p);
    case "decrypt-kek-from-member-envelope":
      return withCryptoOperationError("decryption_failed", () =>
        handleDecryptKekFromMemberEnvelope(state, p),
      );
    case "wrap-kek-with-umk":
      return handleWrapKekWithUmk(state, p);
    case "unwrap-kek-from-backup":
      return withCryptoOperationError("decryption_failed", () =>
        handleUnwrapKekFromBackup(state, p),
      );
    case "encrypt-kek-for-invitation":
      return handleEncryptKekForInvitation(state, p);
    case "decrypt-kek-from-invitation":
      return withCryptoOperationError("decryption_failed", () =>
        handleDecryptKekFromInvitation(state, p),
      );
    case "cache-kek":
      return handleCacheKek(state, p);

    case "sign-pop":
      return withCryptoOperationError("signature_failed", () => handleSignPop(state, p));
    case "sign-ws-envelope":
      return withCryptoOperationError("signature_failed", () => handleSignWsEnvelope(state, p));
    case "sign-message":
      return withCryptoOperationError("signature_failed", () => handleSignMessage(state, p));
    case "sign-device-approval":
      return withCryptoOperationError("signature_failed", () => handleSignDeviceApproval(state, p));
    case "sign-device-registration":
      return withCryptoOperationError("signature_failed", () =>
        handleSignDeviceRegistration(state, p),
      );
    case "sign-recovery-challenge":
      return withCryptoOperationError("signature_failed", () =>
        handleSignRecoveryChallenge(state, p),
      );
    case "sign-session-proof":
      return withCryptoOperationError("signature_failed", () => handleSignSessionProof(state, p));

    case "verify-session-proof":
      return withCryptoOperationError("signature_failed", () => handleVerifySessionProof(p));
    case "verify-ws-signature":
      return withCryptoOperationError("signature_failed", () => handleVerifyWsSignature(p));
    case "verify-ed25519":
      return withCryptoOperationError("signature_failed", () => handleVerifyEd25519(p));
    case "verify-device-identity-signature":
      return withCryptoOperationError("signature_failed", () =>
        handleVerifyDeviceIdentitySignature(p),
      );

    case "compute-update-hash":
      return handleComputeUpdateHash(p);
    case "compute-snapshot-proof":
      return handleComputeSnapshotProof(p);
    case "blake3-hash":
      return handleBlake3Hash(p);
    case "compute-sas":
      return handleComputeSas(p);
    case "calculate-fingerprint":
      return handleCalculateFingerprint(p);

    case "ecdh-encrypt":
      return handleEcdhEncrypt(state, p);
    case "ecdh-decrypt":
      return withCryptoOperationError("decryption_failed", () => handleEcdhDecrypt(state, p));
    case "ecdh-encrypt-umk":
      return handleEcdhEncryptUmk(state, p);
    case "ecdh-decrypt-umk":
      return withCryptoOperationError("decryption_failed", () => handleEcdhDecryptUmk(state, p));

    case "encrypt-trust-state":
      return handleEncryptTrustState(state, p);
    case "decrypt-trust-state":
      return withCryptoOperationError("decryption_failed", () => handleDecryptTrustState(state, p));

    case "tofu-verify":
      return withCryptoOperationError("tofu_hard_fail", () => handleTofuVerify(p));
    case "tofu-verify-all-devices":
      return withCryptoOperationError("tofu_hard_fail", () => handleTofuVerifyAllDevices(state, p));
    case "tofu-trust-device":
      return withCryptoOperationError("tofu_hard_fail", () => handleTofuTrustDevice(p));
    case "tofu-update-last-seen":
      return withCryptoOperationError("tofu_hard_fail", () => handleTofuUpdateLastSeen(p));
    case "tofu-handle-result":
      return withCryptoOperationError("tofu_hard_fail", () => handleTofuHandleResult(p));
    case "tofu-get-all-entries":
      return handleTofuGetAllEntries();
    case "tofu-import-entries":
      return handleTofuImportEntries(p);

    case "encrypt-offline-cache":
      return handleEncryptOfflineCache(state, p);
    case "decrypt-offline-cache":
      return withCryptoOperationError("decryption_failed", () =>
        handleDecryptOfflineCache(state, p),
      );
    case "encrypt-offline-pending":
      return handleEncryptOfflinePending(state, p);
    case "decrypt-offline-pending":
      return withCryptoOperationError("decryption_failed", () =>
        handleDecryptOfflinePending(state, p),
      );
    case "wrap-dek-for-offline":
      return handleWrapDekForOffline(state, p);
    case "unwrap-dek-from-offline":
      return withCryptoOperationError("decryption_failed", () =>
        handleUnwrapDekFromOffline(state, p),
      );
    case "wrap-kek-for-offline":
      return handleWrapKekForOffline(state, p);
    case "unwrap-kek-from-offline":
      return withCryptoOperationError("decryption_failed", () =>
        handleUnwrapKekFromOffline(state, p),
      );

    case "generate-dsk":
      return handleGenerateDskKey(state);

    case "wrap-with-dsk":
      return handleWrapWithDsk(state, p);
    case "unwrap-with-dsk":
      return withCryptoOperationError("decryption_failed", () => handleUnwrapWithDsk(state, p));
    case "wrap-umk-with-dsk":
      return handleWrapUmkWithDsk(state, p);
    case "unwrap-umk-from-dsk":
      return withCryptoOperationError("decryption_failed", () => handleUnwrapUmkFromDsk(state, p));
    case "wrap-device-keys-with-dsk":
      return handleWrapDeviceKeysWithDsk(state, p);
    case "unwrap-device-keys-from-dsk":
      return withCryptoOperationError("decryption_failed", () =>
        handleUnwrapDeviceKeysFromDsk(state, p),
      );

    case "wrap-with-pdk":
      return handleWrapWithPdk(state, p);
    case "unwrap-with-pdk":
      return withCryptoOperationError("decryption_failed", () => handleUnwrapWithPdk(state, p));

    case "generate-invitation-token":
      return handleGenerateInvitationToken();
    case "sha256-hash":
      return handleSha256Hash(p);

    default:
      throw new Error(`Unknown request type: ${request.type}`);
  }
}
