import { getDocumentState } from "@/features/editor";

export function readInitializedDocumentPreviewText(stateKey: string): {
  initialized: boolean;
  text: string;
} {
  const state = getDocumentState(stateKey);
  const contentPreviewReady = Boolean(state?.initialized || state?._verifiedContentPreviewReady);
  if (!state || !contentPreviewReady) {
    return { initialized: false, text: "" };
  }

  const sharedText = state.yDoc.getText("content").toJSON();
  return {
    initialized: contentPreviewReady,
    text: sharedText,
  };
}
