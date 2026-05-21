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

export function getLocalSigningKeyId(state: DocumentState): string | undefined {
  if (state.access.kind !== "share") return undefined;
  return state.access.participantSigningKeyId;
}
