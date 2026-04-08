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
} from "../kek";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const kekRequestHandlers = {
  "cache-kek": (state, payload) => handleCacheKek(state, payload),
  "decrypt-kek-from-device-envelope": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleDecryptKekFromDeviceEnvelope(state, payload),
    ),
  "decrypt-kek-from-invitation": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleDecryptKekFromInvitation(state, payload),
    ),
  "decrypt-kek-from-member-envelope": (state, payload) =>
    withCryptoOperationError("decryption_failed", () =>
      handleDecryptKekFromMemberEnvelope(state, payload),
    ),
  "encrypt-kek-for-device": (state, payload) => handleEncryptKekForDevice(state, payload),
  "encrypt-kek-for-invitation": (state, payload) => handleEncryptKekForInvitation(state, payload),
  "encrypt-kek-for-member": (state, payload) => handleEncryptKekForMember(state, payload),
  "generate-kek": (state, payload) => handleGenerateKek(state, payload),
  "resolve-kek": (state, payload) => handleResolveKek(state, payload),
  "set-active-kek-version": (state, payload) => handleSetActiveKekVersion(state, payload),
  "unwrap-kek-from-backup": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapKekFromBackup(state, payload)),
  "unwrap-kek-from-offline": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleUnwrapKekFromOffline(state, payload)),
  "wrap-kek-for-offline": (state, payload) => handleWrapKekForOffline(state, payload),
  "wrap-kek-with-umk": (state, payload) => handleWrapKekWithUmk(state, payload),
} satisfies RequestHandlerTable;
