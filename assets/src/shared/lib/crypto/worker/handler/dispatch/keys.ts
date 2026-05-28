import {
  handleDeleteGuestInvitationMaterialWithDsk,
  handleDeleteMountTrustAnchorWithDsk,
  handleDeletePluginCredentialWithDsk,
  handleDeleteShareManagementTokenWithDsk,
  handleDeleteShareParticipantSessionWithDsk,
  handleDeleteShareSessionTrustAnchorWithDsk,
  handleDeleteUiStateWithDsk,
  handleClearPluginApplicationDataWithDsk,
  handleClearPluginDataWithDsk,
  handleClearMountTrustAnchorsWithDsk,
  handleClearShareParticipantSessionsWithDsk,
  handleGenerateDskKey,
  handleLoadGuestInvitationMaterialWithDsk,
  handleLoadMountTrustAnchorWithDsk,
  handleLoadPluginCredentialWithDsk,
  handleUnwrapOfflineDocumentTitleWithDsk,
  handleLoadShareManagementTokenWithDsk,
  handleListShareParticipantSessionsWithDsk,
  handleLoadShareSessionTrustAnchorWithDsk,
  handleLoadUiStateWithDsk,
  handlePersistCurrentKeysWithDsk,
  handleUnwrapDeviceKeysFromDsk,
  handleUnwrapUmkFromDsk,
  handleStoreGuestInvitationMaterialWithDsk,
  handleStoreMountTrustAnchorWithDsk,
  handleStorePluginCredentialWithDsk,
  handleWrapOfflineDocumentTitleWithDsk,
  handleStoreShareManagementTokenWithDsk,
  handleStoreShareParticipantSessionWithDsk,
  handleStoreShareSessionTrustAnchorWithDsk,
  handleStoreUiStateWithDsk,
  handleWrapDeviceKeysWithDsk,
  handlePersistShareParticipantKeysWithDsk,
  handleRestoreShareParticipantKeysFromDsk,
} from "../keys/dsk";
import {
  handleGenerateClientNonce,
  handleGenerateDeviceKeys,
  handleGenerateUmk,
  handleGenerateIdentityKeys,
  handleImportIdentityKeys,
  handleImportUmk,
} from "../keys/material";
import { handleGenerateInvitationToken, handleSha256Hash } from "../keys/misc";
import {
  handleDeriveAuthKeys,
  handleDeriveRuk,
  handleGenerateRecoveryKey,
  handleUnwrapUmkWithRuk,
  handleValidateMnemonic,
  handleWrapUmkWithRuk,
} from "../keys/recovery";
import { handleWrapIdentityKeysForServer, handleWrapUmkForServer } from "../keys/server";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const keyRequestHandlers = {
  "derive-auth-keys": (_, payload) => handleDeriveAuthKeys(payload),
  "derive-ruk": (_, payload) => handleDeriveRuk(payload),
  "generate-client-nonce": () => handleGenerateClientNonce(),
  "generate-device-keys": (state, payload) => handleGenerateDeviceKeys(state, payload),
  "generate-dsk": (state) => handleGenerateDskKey(state),
  "persist-current-keys-with-dsk": (state, payload) =>
    handlePersistCurrentKeysWithDsk(state, payload),
  "generate-identity-keys": (state) => handleGenerateIdentityKeys(state),
  "generate-invitation-token": () => handleGenerateInvitationToken(),
  "generate-recovery-key": (state) => handleGenerateRecoveryKey(state),
  "generate-umk": (state) => handleGenerateUmk(state),
  "import-identity-keys": (state, payload) => handleImportIdentityKeys(state, payload),
  "import-umk": (state, payload) => handleImportUmk(state, payload),
  "sha256-hash": (_, payload) => handleSha256Hash(payload),
  "unwrap-device-keys-from-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleUnwrapDeviceKeysFromDsk(state, payload),
    ),
  "restore-share-participant-keys-from-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleRestoreShareParticipantKeysFromDsk(state, payload),
    ),
  "unwrap-umk-from-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapUmkFromDsk(state, payload)),
  "unwrap-umk-with-ruk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapUmkWithRuk(state, payload)),
  "delete-guest-invitation-material-with-dsk": (_state, payload) =>
    handleDeleteGuestInvitationMaterialWithDsk(payload),
  "delete-mount-trust-anchor-with-dsk": (_state, payload) =>
    handleDeleteMountTrustAnchorWithDsk(payload),
  "delete-plugin-credential-with-dsk": (_state, payload) =>
    handleDeletePluginCredentialWithDsk(payload),
  "clear-mount-trust-anchors-with-dsk": () => handleClearMountTrustAnchorsWithDsk(),
  "delete-share-management-token-with-dsk": (_state, payload) =>
    handleDeleteShareManagementTokenWithDsk(payload),
  "delete-share-participant-session-with-dsk": (state, payload) =>
    handleDeleteShareParticipantSessionWithDsk(state, payload),
  "delete-share-session-trust-anchor-with-dsk": (_state, payload) =>
    handleDeleteShareSessionTrustAnchorWithDsk(payload),
  "delete-ui-state-with-dsk": (_state, payload) => handleDeleteUiStateWithDsk(payload),
  "clear-plugin-data-with-dsk": () => handleClearPluginDataWithDsk(),
  "clear-plugin-application-data-with-dsk": (_state, payload) =>
    handleClearPluginApplicationDataWithDsk(payload),
  "clear-share-participant-sessions-with-dsk": () => handleClearShareParticipantSessionsWithDsk(),
  "load-guest-invitation-material-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleLoadGuestInvitationMaterialWithDsk(state, payload),
    ),
  "load-mount-trust-anchor-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleLoadMountTrustAnchorWithDsk(state, payload),
    ),
  "load-plugin-credential-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleLoadPluginCredentialWithDsk(state, payload),
    ),
  "unwrap-offline-document-title-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleUnwrapOfflineDocumentTitleWithDsk(state, payload),
    ),
  "load-share-management-token-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleLoadShareManagementTokenWithDsk(state, payload),
    ),
  "list-share-participant-sessions-with-dsk": (state) =>
    withCryptoOperationError("decryption_failed", () =>
      handleListShareParticipantSessionsWithDsk(state),
    ),
  "load-share-session-trust-anchor-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleLoadShareSessionTrustAnchorWithDsk(state, payload),
    ),
  "load-ui-state-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleLoadUiStateWithDsk(state, payload)),
  "validate-mnemonic": (_, payload) => handleValidateMnemonic(payload),
  "wrap-device-keys-with-dsk": (state, payload) => handleWrapDeviceKeysWithDsk(state, payload),
  "persist-share-participant-keys-with-dsk": (state, payload) =>
    handlePersistShareParticipantKeysWithDsk(state, payload),
  "store-guest-invitation-material-with-dsk": (state, payload) =>
    handleStoreGuestInvitationMaterialWithDsk(state, payload),
  "wrap-identity-keys-for-server": (state, payload) =>
    handleWrapIdentityKeysForServer(state, payload),
  "store-mount-trust-anchor-with-dsk": (state, payload) =>
    handleStoreMountTrustAnchorWithDsk(state, payload),
  "store-plugin-credential-with-dsk": (state, payload) =>
    handleStorePluginCredentialWithDsk(state, payload),
  "wrap-offline-document-title-with-dsk": (state, payload) =>
    handleWrapOfflineDocumentTitleWithDsk(state, payload),
  "store-share-management-token-with-dsk": (state, payload) =>
    handleStoreShareManagementTokenWithDsk(state, payload),
  "store-share-participant-session-with-dsk": (state, payload) =>
    handleStoreShareParticipantSessionWithDsk(state, payload),
  "store-share-session-trust-anchor-with-dsk": (state, payload) =>
    handleStoreShareSessionTrustAnchorWithDsk(state, payload),
  "store-ui-state-with-dsk": (state, payload) => handleStoreUiStateWithDsk(state, payload),
  "wrap-umk-for-server": (state, payload) => handleWrapUmkForServer(state, payload),
  "wrap-umk-with-ruk": (state) => handleWrapUmkWithRuk(state),
} satisfies RequestHandlerTable;
