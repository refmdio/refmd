import { describe, expect, it } from "vite-plus/test";
import { assertBlake3Base64Url, blake3Base64Url } from "./hash";

const enc = new TextEncoder();

describe("BLAKE3 base64url hashes", () => {
  it("matches golden hashes for canonical strings", () => {
    const cases = [
      ['{"a":1,"b":[true,"x"],"c":{"d":2}}', "gEZ-CC60-ZGXR-zjeJshsxng5NNlZsfjuV75BsoG2lU"],
      [
        '{"\\"":"quote","\\\\":"slash","control":"line\\nbreak","emoji":"😀","é":"e-acute"}',
        "4r6J_8lqRQAPRGJJYYNn3XTgzp-UX-TvHjyIqOu2t_s",
      ],
      ['{"A":1,"z":2,"é":3,"€":4}', "DLCESylEclZ2AZGAFcQSJBB8x1QPeP9P1qdcaJToyT8"],
      ['{"n":9007199254740991}', "bzrcA2FCBeTvfTeMUdWEppHGC6oqvN_qUyUBgmGij7Y"],
      ['{"control":"\\u000b\\u001f"}', "pn3t2AxZu1EGyi26Jx1utL15v4TkEbKkhcdtTBfFjnE"],
    ] as const;

    for (const [canonical, hash] of cases) {
      expect(blake3Base64Url(enc.encode(canonical))).toBe(hash);
    }
  });

  it("validates BLAKE3 base64url hashes and sentinels", () => {
    const hash = blake3Base64Url(enc.encode("protocol"));
    expect(hash).toHaveLength(43);
    expect(() => assertBlake3Base64Url(hash)).not.toThrow();
    expect(() => assertBlake3Base64Url("GENESIS")).toThrow();
    expect(() => assertBlake3Base64Url("GENESIS", new Set(["GENESIS"]))).not.toThrow();
    expect(() => assertBlake3Base64Url(`${"A".repeat(42)}_`)).toThrow();
    expect(() =>
      assertBlake3Base64Url("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
    ).toThrow();
  });
});
