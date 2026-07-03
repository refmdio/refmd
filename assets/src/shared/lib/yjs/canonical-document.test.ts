import { describe, expect, test } from "vitest";
import * as Y from "yjs";
import {
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalStateAsUpdate,
  encodeCanonicalStateAsUpdateV2,
  replaceDocWithCanonicalMarkdown,
} from "./canonical-document";

function applyV1(update: Uint8Array): Y.Doc {
  const doc = new Y.Doc();
  Y.applyUpdate(doc, update, "remote");
  return doc;
}

function applyV2(update: Uint8Array): Y.Doc {
  const doc = new Y.Doc();
  Y.applyUpdateV2(doc, update, "remote");
  return doc;
}

describe("canonical-document", () => {
  test("encodes only canonical Markdown text and drops ProseMirror XML", () => {
    const source = new Y.Doc();
    source.getText("content").insert(0, "# Title\n\nbody");
    source.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);

    const encoded = encodeCanonicalStateAsUpdate(source);
    const decoded = applyV1(encoded);

    expect(decoded.getText("content").toString()).toBe("# Title\n\nbody");
    expect(decoded.getXmlFragment("prosemirror").length).toBe(0);

    source.destroy();
    decoded.destroy();
  });

  test("encodes canonical snapshots as V2 updates", () => {
    const source = new Y.Doc();
    source.getText("content").insert(0, "snapshot body");
    source.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("heading")]);

    const encoded = encodeCanonicalStateAsUpdateV2(source);
    const decoded = applyV2(encoded);

    expect(decoded.getText("content").toString()).toBe("snapshot body");
    expect(decoded.getXmlFragment("prosemirror").length).toBe(0);

    source.destroy();
    decoded.destroy();
  });

  test("computes content-only diffs from a canonical baseline", () => {
    const baseline = new Y.Doc();
    baseline.getText("content").insert(0, "alpha");
    const baselineUpdate = encodeCanonicalStateAsUpdate(baseline);

    const source = new Y.Doc();
    source.getText("content").insert(0, "alpha beta");
    source.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);

    const diff = encodeCanonicalDiffAsUpdate(source, baselineUpdate);
    const remote = applyV1(baselineUpdate);
    Y.applyUpdate(remote, diff, "remote");

    expect(remote.getText("content").toString()).toBe("alpha beta");
    expect(remote.getXmlFragment("prosemirror").length).toBe(0);

    baseline.destroy();
    remote.destroy();
    source.destroy();
  });

  test("encodes ProseMirror-only documents as empty canonical Markdown", () => {
    const source = new Y.Doc();
    source.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);
    const decoded = applyV1(encodeCanonicalStateAsUpdate(source));

    expect(decoded.getText("content").toString()).toBe("");
    expect(decoded.getXmlFragment("prosemirror").length).toBe(0);

    source.destroy();
    decoded.destroy();
  });

  test("replaces live content and clears active ProseMirror XML", () => {
    const target = new Y.Doc();
    const source = new Y.Doc();
    target.getText("content").insert(0, "old");
    target.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);
    source.getText("content").insert(0, "new");

    replaceDocWithCanonicalMarkdown(target, source);

    expect(target.getText("content").toString()).toBe("new");
    expect(target.getXmlFragment("prosemirror").length).toBe(0);

    target.destroy();
    source.destroy();
  });
});
