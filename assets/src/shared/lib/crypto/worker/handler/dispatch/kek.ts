import {
  handleCacheKek,
  handleCommitGuestInvitationShareKey,
  handleCreateGenesisWorkspaceMemberEnvelopePrecommit,
  handleCreatePqKekWrapPrecommit,
  handleRewrapInvitationBootstrapForKekRotation,
  handleCreateSignedPqKekWrap,
  handleCreateSignedPqShareLinkSecretBackupWrap,
  handleCreateSignedPqGuestInvitationShareKeyWrap,
  handleDeleteKekForOffline,
  handleDeleteOrphanedKeksForOffline,
  handleFinalizeSignedPqWrapOperationCheckpoint,
  handleBeginInitialAkeKekDelivery,
  handleBeginInitialAkeDeviceStateTransferDelivery,
  handleBeginInitialAkeUmkDelivery,
  handleFinalizeInitialAkeDelivery,
  handleDeleteKekVersion,
  handleGenerateInitialAkeResponderPrekey,
  handleRespondToInitialAkeOffer,
  handleGenerateKek,
  handleOpenInitialAkeUmkDelivery,
  handleOpenInitialAkeKekDelivery,
  handleOpenInitialAkeDeviceStateTransferDelivery,
  handleOpenSignedPqDeviceKekWrap,
  handleOpenRecipientBoundInvitationDeviceKekWrap,
  handleOpenSignedPqMemberKekWrap,
  handleOpenSignedPqShareLinkSecretBackupWrap,
  handleOpenSignedPqGuestInvitationShareKeyWrap,
  handleRestoreGuestInvitationShareKey,
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
  "create-genesis-workspace-member-envelope-precommit": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateGenesisWorkspaceMemberEnvelopePrecommit(state, payload),
    ),
  "create-pq-kek-wrap-precommit": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreatePqKekWrapPrecommit(state, payload),
    ),
  "rewrap-invitation-bootstrap-for-kek-rotation": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleRewrapInvitationBootstrapForKekRotation(state, payload),
    ),
  "create-signed-pq-kek-wrap": (state, payload) =>
    withCryptoOperationError("internal_error", () => handleCreateSignedPqKekWrap(state, payload)),
  "create-signed-pq-share-link-secret-backup-wrap": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateSignedPqShareLinkSecretBackupWrap(state, payload),
    ),
  "create-signed-pq-guest-invitation-share-key-wrap": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleCreateSignedPqGuestInvitationShareKeyWrap(state, payload),
    ),
  "finalize-signed-pq-wrap-operation-checkpoint": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleFinalizeSignedPqWrapOperationCheckpoint(state, payload),
    ),
  "begin-initial-ake-umk-delivery": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleBeginInitialAkeUmkDelivery(state, payload),
    ),
  "begin-initial-ake-kek-delivery": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleBeginInitialAkeKekDelivery(state, payload),
    ),
  "begin-initial-ake-device-state-transfer-delivery": (state, payload) =>
    withCryptoOperationError("internal_error", () =>
      handleBeginInitialAkeDeviceStateTransferDelivery(state, payload),
    ),
  "respond-to-initial-ake-offer": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleRespondToInitialAkeOffer(state, payload),
    ),
  "finalize-initial-ake-delivery": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleFinalizeInitialAkeDelivery(state, payload),
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
  "open-recipient-bound-invitation-device-kek-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenRecipientBoundInvitationDeviceKekWrap(state, payload),
    ),
  "open-signed-pq-member-kek-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenSignedPqMemberKekWrap(state, payload),
    ),
  "open-signed-pq-share-link-secret-backup-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenSignedPqShareLinkSecretBackupWrap(state, payload),
    ),
  "open-signed-pq-guest-invitation-share-key-wrap": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleOpenSignedPqGuestInvitationShareKeyWrap(state, payload),
    ),
  "restore-guest-invitation-share-key": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleRestoreGuestInvitationShareKey(state, payload),
    ),
  "commit-guest-invitation-share-key": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleCommitGuestInvitationShareKey(state, payload),
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
  "delete-kek-version": (state, payload) => handleDeleteKekVersion(state, payload),
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
