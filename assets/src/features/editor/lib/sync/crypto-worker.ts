import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { isRawSharedDocumentAccess } from "../../model/document-state/access";
import type { DocumentState } from "../../model/document-state/types";

export function getDocumentCryptoWorker(state: DocumentState): ReturnType<typeof getCryptoWorker> {
  if (isRawSharedDocumentAccess(state.access)) {
    return getShareParticipantCryptoWorker(state.access.shareSlug);
  }

  return getCryptoWorker();
}
