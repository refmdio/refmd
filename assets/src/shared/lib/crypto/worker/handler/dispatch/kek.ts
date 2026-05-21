import {
  handleCacheKek,
  handleCreateSignedPqKekWrap,
  handleCreateSignedPqShareLinkSecretBackupWrap,
  handleDeleteKekForOffline,
  handleDeleteOrphanedKeksForOffline,
  handleFinalizeSignedPqWrapOperationCheckpoint,
  handleCreateInitialAkeKekDelivery,
  handleCreateInitialAkeDeviceStateTransferDelivery,
  handleCreateInitialAkeUmkDelivery,
  handleGenerateInitialAkeResponderPrekey,
  handleGenerateKek,
  handleOpenInitialAkeUmkDelivery,
  handleOpenInitialAkeKekDelivery,
  handleOpenInitialAkeDeviceStateTransferDelivery,
  handleOpenSignedPqDeviceKekWrap,
  handleOpenSignedPqMemberKekWrap,
  handleOpenSignedPqShareLinkSecretBackupWrap,
  handleResolveKek,
  handleSetActiveKekVersion,
  handleUnwrapKekFromInvitationBootstrap,
  handleLoadOfflineKekMetadata,
  handleRestoreKekFromOffline,
  handleWrapKekForInvitationBootstrap,
  handleStoreKekForOffline,
} from "../kek";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const kekRequestHandlers = {
  "cache-kek": (state, payload) => handleCacheKek(state, payload),
  "create-signed-pq-kek-wrap": (state, payload) =>
    withCryptoOperationError("internal_error", () => handleCreateSignedPqKekWrap(state, payload)),
  "create-signed-pq-share-link-secret-backup-wrap": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateSignedPqShareLinkSecretBackupWrap(state, payload),
    ),
  "finalize-signed-pq-wrap-operation-checkpoint": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleFinalizeSignedPqWrapOperationCheckpoint(state, payload),
    ),
  "create-initial-ake-umk-delivery": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateInitialAkeUmkDelivery(state, payload),
    ),
  "create-initial-ake-kek-delivery": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateInitialAkeKekDelivery(state, payload),
    ),
  "create-initial-ake-device-state-transfer-delivery": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateInitialAkeDeviceStateTransferDelivery(state, payload),
    ),
  "generate-initial-ake-responder-prekey": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleGenerateInitialAkeResponderPrekey(state, payload),
    ),
  "generate-kek": (state, payload) => handleGenerateKek(state, payload),
  "open-signed-pq-device-kek-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenSignedPqDeviceKekWrap(state, payload),
    ),
  "open-signed-pq-member-kek-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenSignedPqMemberKekWrap(state, payload),
    ),
  "open-signed-pq-share-link-secret-backup-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenSignedPqShareLinkSecretBackupWrap(state, payload),
    ),
  "open-initial-ake-umk-delivery": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenInitialAkeUmkDelivery(state, payload),
    ),
  "open-initial-ake-kek-delivery": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenInitialAkeKekDelivery(state, payload),
    ),
  "open-initial-ake-device-state-transfer-delivery": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenInitialAkeDeviceStateTransferDelivery(state, payload),
    ),
  "resolve-kek": (state, payload) => handleResolveKek(state, payload),
  "set-active-kek-version": (state, payload) => handleSetActiveKekVersion(state, payload),
  "unwrap-kek-from-invitation-bootstrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleUnwrapKekFromInvitationBootstrap(state, payload),
    ),
  "restore-kek-from-offline": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleRestoreKekFromOffline(state, payload),
    ),
  "load-offline-kek-metadata": (_state, payload) => handleLoadOfflineKekMetadata(payload),
  "delete-kek-for-offline": (_state, payload) => handleDeleteKekForOffline(payload),
  "delete-orphaned-keks-for-offline": (_state, payload) =>
    handleDeleteOrphanedKeksForOffline(payload),
  "wrap-kek-for-invitation-bootstrap": (state, payload) =>
    handleWrapKekForInvitationBootstrap(state, payload),
  "store-kek-for-offline": (state, payload) => handleStoreKekForOffline(state, payload),
} satisfies RequestHandlerTable;
