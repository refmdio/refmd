import { describe, expect, test } from "vite-plus/test";
import * as Y from "yjs";
import {
  canonicalMarkdownText,
  encodeCanonicalSyncedStateAsUpdate,
} from "@/shared/lib/yjs/canonical-document";
import type { DocumentState } from "../../model/document-state/types";
import { encodeExistingSnapshotCanonicalUpdate } from "./outbound-canonical";

function docWithText(text: string): Y.Doc {
  const doc = new Y.Doc();
  if (text.length > 0) doc.getText("content").insert(0, text);
  return doc;
}

function stateWith(doc: Y.Doc, lastSavedState: Uint8Array | null): DocumentState {
  return { yDoc: doc, lastSavedState } as unknown as DocumentState;
}

describe("outbound canonical update decisions", () => {
  test("does not encode a full update for an existing snapshot without a baseline", () => {
    const live = docWithText("local text");
    try {
      expect(encodeExistingSnapshotCanonicalUpdate(stateWith(live, null))).toEqual({
        kind: "missing_baseline",
      });
    } finally {
      live.destroy();
    }
  });

  test("encodes a structural update when the live document descends from the saved baseline", () => {
    const baseline = docWithText("line 1\nline 2");
    const live = new Y.Doc();
    const merged = new Y.Doc();
    try {
      const baselineState = encodeCanonicalSyncedStateAsUpdate(baseline);
      Y.applyUpdate(live, baselineState, "remote");
      live.getText("content").insert(canonicalMarkdownText(live).length, "\nlocal line");

      const result = encodeExistingSnapshotCanonicalUpdate(stateWith(live, baselineState));

      expect(result.kind).toBe("update");
      if (result.kind !== "update") return;
      Y.applyUpdate(merged, baselineState, "remote");
      Y.applyUpdate(merged, result.update, "remote");
      expect(canonicalMarkdownText(merged)).toBe("line 1\nline 2\nlocal line");
    } finally {
      baseline.destroy();
      live.destroy();
      merged.destroy();
    }
  });

  test("rejects unrelated live text structures against an existing saved baseline", () => {
    const baseline = docWithText("line 1\nline 2");
    const unrelatedLive = docWithText("line 1\nline 2\nlocal line");
    try {
      const baselineState = encodeCanonicalSyncedStateAsUpdate(baseline);

      expect(
        encodeExistingSnapshotCanonicalUpdate(stateWith(unrelatedLive, baselineState)),
      ).toEqual({
        kind: "structural_unavailable",
      });
    } finally {
      baseline.destroy();
      unrelatedLive.destroy();
    }
  });
});
