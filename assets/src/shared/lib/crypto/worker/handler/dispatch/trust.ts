import {
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
