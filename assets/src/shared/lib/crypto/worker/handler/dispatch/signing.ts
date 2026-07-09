import {
  handleBlake3Hash,
  handleCalculateFingerprint,
  handleComputeSas,
  handleComputeUpdateHash,
  handleCreateDeviceApprovalSignature,
  handleSignDeviceKeyDeletionProof,
  handleCreateGenesisDeviceBootstrapSignature,
  handleCreateRecoveryDeviceApprovalSignature,
  handleCreateDeviceRevocationSignature,
  handleVerifyDeviceApprovalProof,
  handleVerifyGenesisDeviceBootstrapProof,
  handleVerifyRecoveryDeviceApprovalProof,
  handleSignDocumentSnapshot,
  handleSignDocumentUpdate,
  handleSignEditorEphemeral,
  handleGenerateInvitationRedeemAuthority,
  handleSignDeviceKeyDirectoryCheckpoint,
  handleSignDeviceKeyDirectoryEvent,
  handleSignIdentityKeyDirectoryCheckpoint,
  handleSignIdentityKeyDirectoryEvent,
  handleSignInvitationRedeemKeyDirectoryCheckpoint,
  handleSignInvitationRedeemKeyDirectoryEvent,
  handleSignPluginConsentEvent,
  handleSignPluginBundleApproval,
  handleSignPluginNetworkProxyRequest,
  handleSignShareParticipantDeviceKeyDirectoryCheckpoint,
  handleSignShareParticipantDeviceKeyDirectoryEvent,
  handleSignWorkspacePinBootstrap,
  handleCreateRrpSignature,
  handleSignRecoverySession,
  handleSignShareCapabilityAuthorization,
  handleCreateEditorEphemeralSessionProof,
  handleSignShareParticipantDeviceAuthorization,
  handleSignRecipientBoundAuthorization,
  handleVerifyDocumentSnapshotSignature,
  handleVerifyDocumentUpdateEd25519Signature,
  handleVerifyDocumentUpdateSignature,
  handleVerifyEditorEphemeralSignature,
  handleVerifyKeyDirectoryCheckpointSignature,
  handleVerifyKeyDirectoryEventSignature,
  handleVerifyWorkspacePinBootstrapSignature,
  handleVerifyEditorEphemeralSessionProof,
} from "../sign";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const signingRequestHandlers = {
  "blake3-hash": (_, payload) => handleBlake3Hash(payload),
  "calculate-fingerprint": (_, payload) => handleCalculateFingerprint(payload),
  "compute-sas": (_, payload) => handleComputeSas(payload),
  "compute-update-hash": (_, payload) => handleComputeUpdateHash(payload),
  "create-device-approval-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleCreateDeviceApprovalSignature(state, payload),
    ),
  "create-genesis-device-bootstrap-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleCreateGenesisDeviceBootstrapSignature(state, payload),
    ),
  "create-recovery-device-approval-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleCreateRecoveryDeviceApprovalSignature(state, payload),
    ),
  "create-device-revocation-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleCreateDeviceRevocationSignature(state, payload),
    ),
  "sign-device-key-deletion-proof": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignDeviceKeyDeletionProof(state, payload),
    ),
  "sign-identity-key-directory-checkpoint": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignIdentityKeyDirectoryCheckpoint(state, payload),
    ),
  "sign-device-key-directory-checkpoint": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignDeviceKeyDirectoryCheckpoint(state, payload),
    ),
  "sign-share-participant-device-key-directory-checkpoint": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignShareParticipantDeviceKeyDirectoryCheckpoint(state, payload),
    ),
  "sign-identity-key-directory-event": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignIdentityKeyDirectoryEvent(state, payload),
    ),
  "sign-device-key-directory-event": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignDeviceKeyDirectoryEvent(state, payload),
    ),
  "sign-share-participant-device-key-directory-event": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignShareParticipantDeviceKeyDirectoryEvent(state, payload),
    ),
  "sign-workspace-pin-bootstrap": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignWorkspacePinBootstrap(state, payload),
    ),
  "sign-plugin-consent-event": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignPluginConsentEvent(state, payload),
    ),
  "sign-plugin-bundle-approval": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignPluginBundleApproval(state, payload),
    ),
  "sign-plugin-network-proxy-request": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignPluginNetworkProxyRequest(state, payload),
    ),
  "generate-invitation-redeem-authority": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleGenerateInvitationRedeemAuthority(state, payload),
    ),
  "sign-invitation-redeem-key-directory-event": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignInvitationRedeemKeyDirectoryEvent(state, payload),
    ),
  "sign-invitation-redeem-key-directory-checkpoint": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignInvitationRedeemKeyDirectoryCheckpoint(state, payload),
    ),
  "sign-recipient-bound-authorization": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignRecipientBoundAuthorization(state, payload),
    ),
  "create-rrp-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleCreateRrpSignature(state, payload)),
  "sign-recovery-session": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignRecoverySession(state, payload)),
  "sign-share-capability-authorization": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignShareCapabilityAuthorization(state, payload),
    ),
  "sign-share-participant-device-authorization": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignShareParticipantDeviceAuthorization(state, payload),
    ),
  "create-editor-ephemeral-session-proof": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleCreateEditorEphemeralSessionProof(state, payload),
    ),
  "sign-document-update": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignDocumentUpdate(state, payload)),
  "sign-document-snapshot": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignDocumentSnapshot(state, payload)),
  "sign-editor-ephemeral": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignEditorEphemeral(state, payload)),
  "verify-genesis-device-bootstrap-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyGenesisDeviceBootstrapProof(state, payload),
    ),
  "verify-device-approval-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyDeviceApprovalProof(state, payload),
    ),
  "verify-recovery-device-approval-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyRecoveryDeviceApprovalProof(state, payload),
    ),
  "verify-editor-ephemeral-session-proof": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyEditorEphemeralSessionProof(state, payload),
    ),
  "verify-key-directory-checkpoint-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyKeyDirectoryCheckpointSignature(state, payload),
    ),
  "verify-key-directory-event-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyKeyDirectoryEventSignature(state, payload),
    ),
  "verify-workspace-pin-bootstrap-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyWorkspacePinBootstrapSignature(state, payload),
    ),
  "verify-document-update-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyDocumentUpdateSignature(state, payload),
    ),
  "verify-document-update-ed25519-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyDocumentUpdateEd25519Signature(state, payload),
    ),
  "verify-document-snapshot-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyDocumentSnapshotSignature(state, payload),
    ),
  "verify-editor-ephemeral-signature": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyEditorEphemeralSignature(state, payload),
    ),
} satisfies RequestHandlerTable;
