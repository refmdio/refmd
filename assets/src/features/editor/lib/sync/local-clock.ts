import type { DocumentState } from "../../model/document-state/types";
import { getNextClockForDevice } from "@/shared/lib/anti-rollback/clock-observations";

export function localAuthorityContextKey(
  state: DocumentState,
  signingKeyId?: string | null,
): string | undefined {
  if (state.access.kind === "share") {
    const authorityId = state.access.authorizationShareId ?? state.access.shareId;
    return `${authorityId}:${state.access.participantPrincipalId}`;
  }
  return signingKeyId ?? undefined;
}

export function localDocumentClockKey(
  state: DocumentState,
  signingKeyId?: string | null,
): string | undefined {
  if (!signingKeyId) return undefined;
  const authorityContextKey = localAuthorityContextKey(state, signingKeyId);
  return authorityContextKey ? `${authorityContextKey}:${signingKeyId}` : signingKeyId;
}

export function nextLocalClockForDevice(
  clocks: Record<string, number>,
  state: DocumentState,
  signingKeyId?: string | null,
): number {
  return getNextClockForDevice(
    clocks,
    signingKeyId,
    localAuthorityContextKey(state, signingKeyId),
  );
}
