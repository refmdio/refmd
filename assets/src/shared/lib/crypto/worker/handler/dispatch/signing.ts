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
} from "../sign";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const signingRequestHandlers = {
  "blake3-hash": (_, payload) => handleBlake3Hash(payload),
  "calculate-fingerprint": (_, payload) => handleCalculateFingerprint(payload),
  "compute-sas": (_, payload) => handleComputeSas(payload),
  "compute-snapshot-proof": (_, payload) => handleComputeSnapshotProof(payload),
  "compute-update-hash": (_, payload) => handleComputeUpdateHash(payload),
  "sign-device-approval": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignDeviceApproval(state, payload)),
  "sign-device-registration": (state, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleSignDeviceRegistration(state, payload),
    ),
  "sign-message": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignMessage(state, payload)),
  "sign-pop": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignPop(state, payload)),
  "sign-recovery-challenge": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignRecoveryChallenge(state, payload)),
  "sign-session-proof": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignSessionProof(state, payload)),
  "sign-ws-envelope": (state, payload) =>
    withCryptoOperationError("signature_failed", () => handleSignWsEnvelope(state, payload)),
  "verify-device-identity-signature": (_, payload) =>
    withCryptoOperationError("signature_failed", () =>
      handleVerifyDeviceIdentitySignature(payload),
    ),
  "verify-ed25519": (_, payload) =>
    withCryptoOperationError("signature_failed", () => handleVerifyEd25519(payload)),
  "verify-session-proof": (_, payload) =>
    withCryptoOperationError("signature_failed", () => handleVerifySessionProof(payload)),
  "verify-ws-signature": (_, payload) =>
    withCryptoOperationError("signature_failed", () => handleVerifyWsSignature(payload)),
} satisfies RequestHandlerTable;
