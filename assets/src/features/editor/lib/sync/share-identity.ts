import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import type { DocumentState } from "../../model/document-state/types";

export function getLocalDeviceId(state: DocumentState): string | null {
  if (state.access.kind !== "share") return null;
  return state.access.participantDeviceId;
}

export function getLocalIdentity(state: DocumentState): {
  id: string;
  name: string;
  colorSeed: string;
} | null {
  if (state.access.kind !== "share") return null;
  return {
    id: state.access.participantPrincipalId,
    name: state.access.participantDisplayName,
    colorSeed: state.access.participantPrincipalId,
  };
}

export function getLocalSigningPubKeyB64(state: DocumentState): string | undefined {
  if (state.access.kind !== "share") return undefined;
  return state.access.participantSigningPublicKey;
}

export function getLocalSigningPublicKeyBytes(state: DocumentState): Uint8Array | null {
  if (state.access.kind !== "share") return null;
  return base64UrlDecode(state.access.participantSigningPublicKey);
}

export function getLocalSigningPubKeyOrEncode(
  state: DocumentState,
  bytes: Uint8Array | null | undefined,
): string | undefined {
  return getLocalSigningPubKeyB64(state) ?? (bytes ? base64UrlEncode(bytes) : undefined);
}
