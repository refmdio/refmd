import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import type { DocumentState } from "../../model/document-state/types";

export function getDocumentCryptoWorker(state: DocumentState): ReturnType<typeof getCryptoWorker> {
  if (state.access.kind === "share") {
    return getShareParticipantCryptoWorker(state.access.shareSlug);
  }

  return getCryptoWorker();
}
