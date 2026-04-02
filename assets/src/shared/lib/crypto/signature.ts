import { canonicalizeBytes } from "./aad";
const SIGNATURE_PROTOCOL = {
  protocol: "refmd",
  version: 1,
} as const;
export const SIGNATURE_ACTION = {
  TRUST_STATE_TRANSFER: "transfer_trust_state",
  POP_CHALLENGE: "pop_challenge",
  DEVICE_APPROVAL: "device_approval",
  DEVICE_REGISTRATION: "device_registration",
  DEVICE_REVOCATION: "device_revocation",
} as const;
export function buildSignatureMessage(
  action: string,
  payload: Record<string, unknown>,
): Uint8Array {
  return canonicalizeBytes({
    ...SIGNATURE_PROTOCOL,
    action,
    ...payload,
  });
}
