import { describe, expect, test } from "vite-plus/test";
import { hasCanonicalLocalChanges } from "./inbound-document-decisions";

describe("inbound document decisions", () => {
  test("treats delete-to-empty against a saved baseline as a local change", () => {
    expect(
      hasCanonicalLocalChanges({
        savedText: "draft",
        liveText: "",
        serverText: "draft remote",
      }),
    ).toBe(true);
  });

  test("does not treat an empty no-baseline document as a local change", () => {
    expect(
      hasCanonicalLocalChanges({
        savedText: null,
        liveText: "",
        serverText: "remote",
      }),
    ).toBe(false);
  });
});
