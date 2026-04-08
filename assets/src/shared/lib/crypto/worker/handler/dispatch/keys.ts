import {
  handleGenerateDskKey,
  handleUnwrapDeviceKeysFromDsk,
  handleUnwrapUmkFromDsk,
  handleUnwrapWithDsk,
  handleWrapDeviceKeysWithDsk,
  handleWrapUmkWithDsk,
  handleWrapWithDsk,
} from "../keys/dsk";
import {
  handleGenerateClientNonce,
  handleGenerateDeviceKeys,
  handleGenerateUmk,
  handleGenerateIdentityKeys,
  handleImportDeviceKeys,
  handleImportIdentityKeys,
  handleImportUmk,
} from "../keys/material";
import { handleGenerateInvitationToken, handleSha256Hash } from "../keys/misc";
import { handleUnwrapWithPdk, handleWrapWithPdk } from "../keys/pdk";
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
  "generate-device-keys": (state) => handleGenerateDeviceKeys(state),
  "generate-dsk": (state) => handleGenerateDskKey(state),
  "generate-identity-keys": (state) => handleGenerateIdentityKeys(state),
  "generate-invitation-token": () => handleGenerateInvitationToken(),
  "generate-recovery-key": (state) => handleGenerateRecoveryKey(state),
  "generate-umk": (state) => handleGenerateUmk(state),
  "import-device-keys": (state, payload) => handleImportDeviceKeys(state, payload),
  "import-identity-keys": (state, payload) => handleImportIdentityKeys(state, payload),
  "import-umk": (state, payload) => handleImportUmk(state, payload),
  "sha256-hash": (_, payload) => handleSha256Hash(payload),
  "unwrap-device-keys-from-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleUnwrapDeviceKeysFromDsk(state, payload),
    ),
  "unwrap-umk-from-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapUmkFromDsk(state, payload)),
  "unwrap-umk-with-ruk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapUmkWithRuk(state, payload)),
  "unwrap-with-dsk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapWithDsk(state, payload)),
  "unwrap-with-pdk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapWithPdk(state, payload)),
  "validate-mnemonic": (_, payload) => handleValidateMnemonic(payload),
  "wrap-device-keys-with-dsk": (state, payload) => handleWrapDeviceKeysWithDsk(state, payload),
  "wrap-identity-keys-for-server": (state, payload) =>
    handleWrapIdentityKeysForServer(state, payload),
  "wrap-umk-for-server": (state, payload) => handleWrapUmkForServer(state, payload),
  "wrap-umk-with-dsk": (state, payload) => handleWrapUmkWithDsk(state, payload),
  "wrap-umk-with-ruk": (state) => handleWrapUmkWithRuk(state),
  "wrap-with-dsk": (state, payload) => handleWrapWithDsk(state, payload),
  "wrap-with-pdk": (state, payload) => handleWrapWithPdk(state, payload),
} satisfies RequestHandlerTable;
