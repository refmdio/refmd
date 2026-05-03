import {
  handleEcdhDecrypt,
  handleEcdhDecryptUmk,
  handleEcdhEncrypt,
  handleEcdhEncryptUmk,
} from "../ecdh";
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
} from "../tofu";
import { withCryptoOperationError } from "../utils";
import type { RequestHandlerTable } from "./shared";

export const trustRequestHandlers = {
  "decrypt-trust-state": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleDecryptTrustState(state, payload)),
  "ecdh-decrypt": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleEcdhDecrypt(state, payload)),
  "ecdh-decrypt-umk": (state, payload) =>
    withCryptoOperationError("decryption_failed", () => handleEcdhDecryptUmk(state, payload)),
  "ecdh-encrypt": (state, payload) => handleEcdhEncrypt(state, payload),
  "ecdh-encrypt-umk": (state, payload) => handleEcdhEncryptUmk(state, payload),
  "encrypt-trust-state": (state, payload) => handleEncryptTrustState(state, payload),
  "tofu-get-all-entries": (_, payload) => handleTofuGetAllEntries(payload),
  "tofu-handle-result": (_, payload) =>
    withCryptoOperationError("tofu_hard_fail", () => handleTofuHandleResult(payload)),
  "tofu-import-entries": (_, payload) => handleTofuImportEntries(payload),
  "tofu-trust-device": (_, payload) =>
    withCryptoOperationError("tofu_hard_fail", () => handleTofuTrustDevice(payload)),
  "tofu-update-last-seen": (_, payload) =>
    withCryptoOperationError("tofu_hard_fail", () => handleTofuUpdateLastSeen(payload)),
  "tofu-verify": (_, payload) =>
    withCryptoOperationError("tofu_hard_fail", () => handleTofuVerify(payload)),
  "tofu-verify-all-devices": (state, payload) =>
    withCryptoOperationError("tofu_hard_fail", () => handleTofuVerifyAllDevices(state, payload)),
} satisfies RequestHandlerTable;
