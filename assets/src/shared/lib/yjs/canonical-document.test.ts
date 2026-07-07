import { describe, expect, test } from "vite-plus/test";
import * as Y from "yjs";
import {
  clearProseMirrorXml,
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalStateAsUpdate,
  encodeCanonicalStateAsUpdateV2,
  encodeCanonicalSyncedStateAsUpdate,
  replaceDocWithCanonicalText,
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

    const source = applyV1(baselineUpdate);
    source.getText("content").insert(source.getText("content").length, " beta");
    source.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);

    const diff = encodeCanonicalDiffAsUpdate(source, baselineUpdate);
    const remote = applyV1(baselineUpdate);
    expect(diff).not.toBeNull();
    Y.applyUpdate(remote, diff!, "remote");

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

  test("replaces live content created from different CRDT structs", () => {
    const target = new Y.Doc();
    const source = new Y.Doc();
    target.getText("content").insert(0, "From device A. ");
    source.getText("content").insert(0, "From device A. \nFrom device B. ");

    replaceDocWithCanonicalText(target, source.getText("content").toString(), "remote");

    expect(target.getText("content").toString()).toBe("From device A. \nFrom device B. ");

    target.destroy();
    source.destroy();
  });

  test("preserves server CRDT structs so later device diffs compose", () => {
    const deviceA = new Y.Doc();
    const server = new Y.Doc();
    deviceA.getText("content").insert(0, "From device A. ");
    const updateFromA = encodeCanonicalDiffAsUpdate(deviceA, null);
    expect(updateFromA).not.toBeNull();
    Y.applyUpdate(server, updateFromA!, "remote");
    const serverBaseline = Y.encodeStateAsUpdate(server);

    const deviceB = new Y.Doc();
    Y.applyUpdate(deviceB, serverBaseline, "remote");
    deviceB.getText("content").insert(deviceB.getText("content").length, "\nFrom device B. ");
    const updateFromB = encodeCanonicalDiffAsUpdate(deviceB, serverBaseline);
    expect(updateFromB).not.toBeNull();

    Y.applyUpdate(server, updateFromB!, "remote");

    expect(server.getText("content").toString()).toBe("From device A. \nFrom device B. ");

    deviceA.destroy();
    deviceB.destroy();
    server.destroy();
  });

  test("composes independent same-baseline edits without last-writer replacement", () => {
    const baseline = new Y.Doc();
    baseline.getText("content").insert(0, "base");
    const baselineUpdate = encodeCanonicalStateAsUpdate(baseline);
    const server = applyV1(baselineUpdate);

    const deviceA = applyV1(baselineUpdate);
    const deviceB = applyV1(baselineUpdate);
    deviceA.getText("content").insert(0, "A ");
    deviceB.getText("content").insert(deviceB.getText("content").length, " B");

    const updateFromA = encodeCanonicalDiffAsUpdate(deviceA, baselineUpdate);
    const updateFromB = encodeCanonicalDiffAsUpdate(deviceB, baselineUpdate);
    expect(updateFromA).not.toBeNull();
    expect(updateFromB).not.toBeNull();
    Y.applyUpdate(server, updateFromA!, "remote");
    Y.applyUpdate(server, updateFromB!, "remote");

    expect(server.getText("content").toString()).toBe("A base B");

    baseline.destroy();
    deviceA.destroy();
    deviceB.destroy();
    server.destroy();
  });

  test("keeps the saved baseline server-only after merging into a live local document", () => {
    const server = new Y.Doc();
    server.getText("content").insert(0, "server");
    const serverOnlyBaseline = encodeCanonicalSyncedStateAsUpdate(server);

    const live = new Y.Doc();
    live.getText("content").insert(0, "local ");
    Y.applyUpdate(live, serverOnlyBaseline, "remote");

    const pendingLocalUpdate = encodeCanonicalDiffAsUpdate(live, serverOnlyBaseline);
    expect(pendingLocalUpdate).not.toBeNull();
    Y.applyUpdate(server, pendingLocalUpdate!, "remote");

    const text = server.getText("content").toString();
    expect(text).toContain("local");
    expect(text).toContain("server");
    expect(text.match(/local/g) ?? []).toHaveLength(1);
    expect(text.match(/server/g) ?? []).toHaveLength(1);

    live.destroy();
    server.destroy();
  });

  test("applies a re-encoded snapshot by text replacement without duplicating live content", () => {
    const snapshotSource = new Y.Doc();
    snapshotSource.getText("content").insert(0, "snapshot body");
    const snapshotDoc = applyV2(encodeCanonicalStateAsUpdateV2(snapshotSource));

    const live = new Y.Doc();
    live.getText("content").insert(0, "snapshot body");
    Y.applyUpdate(live, encodeCanonicalSyncedStateAsUpdate(snapshotDoc), "remote");
    expect(live.getText("content").toString()).toBe("snapshot bodysnapshot body");

    replaceDocWithCanonicalText(live, snapshotDoc.getText("content").toString(), "remote");
    expect(live.getText("content").toString()).toBe("snapshot body");

    snapshotSource.destroy();
    snapshotDoc.destroy();
    live.destroy();
  });

  test("applies a remote update after text-replaced snapshot without duplicating baseline text", () => {
    const snapshotSource = new Y.Doc();
    snapshotSource.getText("content").insert(0, "snapshot body");
    const server = applyV2(encodeCanonicalStateAsUpdateV2(snapshotSource));
    const serverBaseline = encodeCanonicalSyncedStateAsUpdate(server);

    const remoteDevice = applyV1(serverBaseline);
    remoteDevice.getText("content").insert(remoteDevice.getText("content").length, " updated");
    const remoteUpdate = encodeCanonicalDiffAsUpdate(remoteDevice, serverBaseline);
    expect(remoteUpdate).not.toBeNull();
    Y.applyUpdate(server, remoteUpdate!, "remote");

    const live = new Y.Doc();
    replaceDocWithCanonicalText(live, "snapshot body", "remote");
    const duplicate = applyV1(Y.encodeStateAsUpdate(live));
    Y.applyUpdate(duplicate, encodeCanonicalSyncedStateAsUpdate(server), "remote");
    const duplicatedText = duplicate.getText("content").toString();
    expect(duplicatedText).toContain("snapshot body updated");
    expect(duplicatedText.match(/snapshot body/g) ?? []).toHaveLength(2);

    replaceDocWithCanonicalText(live, "", "remote");
    Y.applyUpdate(live, encodeCanonicalSyncedStateAsUpdate(server), "remote");
    clearProseMirrorXml(live, "remote");
    expect(live.getText("content").toString()).toBe("snapshot body updated");

    snapshotSource.destroy();
    server.destroy();
    remoteDevice.destroy();
    live.destroy();
    duplicate.destroy();
  });

  test("restores server structs after a text reset so later local diffs keep ancestry", () => {
    const snapshotSource = new Y.Doc();
    snapshotSource.getText("content").insert(0, "line 1\nline 2");
    const server = applyV2(encodeCanonicalStateAsUpdateV2(snapshotSource));
    const serverBaseline = encodeCanonicalSyncedStateAsUpdate(server);

    const unrelatedLive = new Y.Doc();
    replaceDocWithCanonicalText(unrelatedLive, "line 1\nline 2", "remote");
    unrelatedLive.getText("content").insert("line 1\n".length, "local\n");
    expect(encodeCanonicalDiffAsUpdate(unrelatedLive, serverBaseline)).toBeNull();

    const live = new Y.Doc();
    replaceDocWithCanonicalText(live, "line 1\nline 2", "remote");
    replaceDocWithCanonicalText(live, "", "remote");
    Y.applyUpdate(live, serverBaseline, "remote");
    live.getText("content").insert("line 1\n".length, "local\n");

    const diff = encodeCanonicalDiffAsUpdate(live, serverBaseline);
    const merged = applyV1(serverBaseline);
    expect(diff).not.toBeNull();
    Y.applyUpdate(merged, diff!, "remote");

    expect(merged.getText("content").toString()).toBe("line 1\nlocal\nline 2");

    snapshotSource.destroy();
    server.destroy();
    unrelatedLive.destroy();
    live.destroy();
    merged.destroy();
  });

  test("rebases local text onto a re-encoded matching server baseline", () => {
    const saved = new Y.Doc();
    saved.getText("content").insert(0, "Line 0 test. \n");
    const savedState = encodeCanonicalSyncedStateAsUpdate(saved);

    const live = applyV1(savedState);
    live.getText("content").insert(live.getText("content").length, "Line 1 test. \n");
    live.getText("content").insert(live.getText("content").length, "Line 2 test. \n");
    const liveText = live.getText("content").toString();

    const snapshotSource = new Y.Doc();
    snapshotSource.getText("content").insert(0, "Line 0 test. \n");
    const reencodedServer = applyV2(encodeCanonicalStateAsUpdateV2(snapshotSource));
    const serverBaseline = encodeCanonicalSyncedStateAsUpdate(reencodedServer);

    const directLocalUpdate = encodeCanonicalDiffAsUpdate(live, savedState);
    expect(directLocalUpdate).not.toBeNull();
    const directMerge = applyV1(serverBaseline);
    Y.applyUpdate(directMerge, directLocalUpdate!, "remote");
    expect(directMerge.getText("content").toString()).toBe("Line 0 test. \n");

    replaceDocWithCanonicalText(live, "", "remote");
    Y.applyUpdate(live, serverBaseline, "remote");
    replaceDocWithCanonicalText(live, liveText, "remote");

    const rebasedLocalUpdate = encodeCanonicalDiffAsUpdate(live, serverBaseline);
    expect(rebasedLocalUpdate).not.toBeNull();
    const rebasedMerge = applyV1(serverBaseline);
    Y.applyUpdate(rebasedMerge, rebasedLocalUpdate!, "remote");
    expect(rebasedMerge.getText("content").toString()).toBe(liveText);

    saved.destroy();
    live.destroy();
    snapshotSource.destroy();
    reencodedServer.destroy();
    directMerge.destroy();
    rebasedMerge.destroy();
  });

  test("encodes a semantic no-op canonical diff as an empty update", () => {
    const baseline = new Y.Doc();
    baseline.getText("content").insert(0, "same text");
    const baselineUpdate = encodeCanonicalSyncedStateAsUpdate(baseline);

    const live = applyV1(baselineUpdate);
    live.getText("content").insert(live.getText("content").length, "!");
    live.getText("content").delete(live.getText("content").length - 1, 1);

    const diff = encodeCanonicalDiffAsUpdate(live, baselineUpdate);
    const remote = applyV1(baselineUpdate);
    expect(diff).not.toBeNull();
    Y.applyUpdate(remote, diff!, "remote");

    expect(diff!.length).toBeLessThanOrEqual(2);
    expect(remote.getText("content").toString()).toBe("same text");

    baseline.destroy();
    live.destroy();
    remote.destroy();
  });

  test("does not synthesize text-only diffs from unrelated Yjs structs", () => {
    const baseline = new Y.Doc();
    baseline.getText("content").insert(0, "alpha\n");
    const baselineUpdate = encodeCanonicalSyncedStateAsUpdate(baseline);

    const unrelatedLive = new Y.Doc();
    unrelatedLive.getText("content").insert(0, "alpha\nlocal\n");

    expect(encodeCanonicalDiffAsUpdate(unrelatedLive, baselineUpdate)).toBeNull();

    baseline.destroy();
    unrelatedLive.destroy();
  });

  test("does not synthesize repeated-line text diffs without CRDT ancestry", () => {
    const baseline = new Y.Doc();
    baseline.getText("content").insert(0, Array.from({ length: 600 }, () => "same\n").join(""));
    const baselineUpdate = encodeCanonicalSyncedStateAsUpdate(baseline);

    const unrelatedLive = new Y.Doc();
    const lines = Array.from({ length: 600 }, () => "same\n");
    lines[10] = "local first\n";
    lines[590] = "local last\n";
    unrelatedLive.getText("content").insert(0, lines.join(""));

    expect(encodeCanonicalDiffAsUpdate(unrelatedLive, baselineUpdate)).toBeNull();

    baseline.destroy();
    unrelatedLive.destroy();
  });

  test("documents Yjs delete-then-apply snapshot hazard", () => {
    const live = new Y.Doc();
    live.getText("content").insert(0, "A");
    const server = applyV1(Y.encodeStateAsUpdate(live));
    server.getText("content").insert(server.getText("content").length, "B");
    const serverUpdate = encodeCanonicalSyncedStateAsUpdate(server);

    const tombstoned = applyV1(Y.encodeStateAsUpdate(live));
    replaceDocWithCanonicalText(tombstoned, "", "remote");
    Y.applyUpdate(tombstoned, serverUpdate, "remote");
    expect(tombstoned.getText("content").toString()).toBe("B");

    const applied = applyV1(Y.encodeStateAsUpdate(live));
    Y.applyUpdate(applied, serverUpdate, "remote");
    expect(applied.getText("content").toString()).toBe("AB");

    live.destroy();
    server.destroy();
    tombstoned.destroy();
    applied.destroy();
  });

  test("clears ProseMirror XML without rewriting canonical text structs", () => {
    const doc = new Y.Doc();
    doc.getText("content").insert(0, "body");
    doc.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);

    clearProseMirrorXml(doc);

    expect(doc.getText("content").toString()).toBe("body");
    expect(doc.getXmlFragment("prosemirror").length).toBe(0);

    doc.destroy();
  });
});
