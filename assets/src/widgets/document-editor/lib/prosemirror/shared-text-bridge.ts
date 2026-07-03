import * as Y from "yjs";
import { ORIGIN_INIT } from "@pm-cm/yjs";
import { replaceYTextWithMinimalDiff } from "@/shared/lib/yjs/canonical-document";
import { ensureYDocMarkdownText } from "./preview-text";

const SHARED_TO_WYSIWYG_ORIGIN = "refmd:shared-content-to-wysiwyg";
const WYSIWYG_TO_SHARED_ORIGIN = "refmd:wysiwyg-content-to-shared";

export interface LocalProseMirrorBridgeDoc {
  yDoc: Y.Doc;
  yText: Y.Text;
  dispose: () => void;
}

export function createLocalProseMirrorBridgeDoc(sharedDoc: Y.Doc): LocalProseMirrorBridgeDoc {
  const sharedText = ensureYDocMarkdownText(sharedDoc);
  const bridgeDoc = new Y.Doc();
  const bridgeText = bridgeDoc.getText("content");

  if (sharedText.length > 0) {
    bridgeText.insert(0, sharedText.toString());
  }

  const mirrorSharedToBridge = (
    _event: unknown,
    transaction?: {
      origin?: unknown;
    },
  ) => {
    if (transaction?.origin === WYSIWYG_TO_SHARED_ORIGIN) return;
    bridgeDoc.transact(() => {
      replaceYTextWithMinimalDiff(bridgeText, sharedText.toString());
    }, SHARED_TO_WYSIWYG_ORIGIN);
  };

  const mirrorBridgeToShared = (
    _event: unknown,
    transaction?: {
      origin?: unknown;
    },
  ) => {
    if (transaction?.origin === SHARED_TO_WYSIWYG_ORIGIN) return;
    if (transaction?.origin === ORIGIN_INIT) return;
    sharedDoc.transact(() => {
      replaceYTextWithMinimalDiff(sharedText, bridgeText.toString());
    }, WYSIWYG_TO_SHARED_ORIGIN);
  };

  sharedText.observe(mirrorSharedToBridge);
  bridgeText.observe(mirrorBridgeToShared);

  let disposed = false;
  return {
    yDoc: bridgeDoc,
    yText: bridgeText,
    dispose: () => {
      if (disposed) return;
      disposed = true;
      sharedText.unobserve(mirrorSharedToBridge);
      bridgeText.unobserve(mirrorBridgeToShared);
      bridgeDoc.destroy();
    },
  };
}
