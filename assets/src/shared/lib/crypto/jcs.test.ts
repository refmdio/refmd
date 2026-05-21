import { describe, expect, it } from "vitest";
import {
  canonicalizeStrict,
  canonicalizeStrictBytes,
  parseJsonStrict,
  parseJsonStrictBytes,
  type StrictJsonValue,
} from "./jcs";

const enc = new TextEncoder();

describe("strict JCS", () => {
  it("matches golden canonical bytes", () => {
    const cases: { value: StrictJsonValue; canonical: string }[] = [
      {
        value: { c: { d: 2 }, b: [true, "x"], a: 1 },
        canonical: '{"a":1,"b":[true,"x"],"c":{"d":2}}',
      },
      {
        value: {
          '"': "quote",
          "\\": "slash",
          control: "line\nbreak",
          emoji: "😀",
          é: "e-acute",
        },
        canonical:
          '{"\\"":"quote","\\\\":"slash","control":"line\\nbreak","emoji":"😀","é":"e-acute"}',
      },
      {
        value: { "€": 4, z: 2, é: 3, A: 1 },
        canonical: '{"A":1,"z":2,"é":3,"€":4}',
      },
      {
        value: { n: 9_007_199_254_740_991 },
        canonical: '{"n":9007199254740991}',
      },
      {
        value: { control: "\u000b\u001f" },
        canonical: '{"control":"\\u000b\\u001f"}',
      },
    ];

    for (const testCase of cases) {
      expect(canonicalizeStrict(testCase.value)).toBe(testCase.canonical);
      expect(canonicalizeStrictBytes(testCase.value)).toEqual(enc.encode(testCase.canonical));
    }
  });

  it("rejects non-strict values and raw JSON syntax", () => {
    expect(() => canonicalizeStrict({ a: null as never })).toThrow();
    expect(() => canonicalizeStrict({ a: undefined as never })).toThrow();
    expect(() => canonicalizeStrict({ a: -1 })).toThrow();
    expect(() => canonicalizeStrict({ a: 9_007_199_254_740_992 })).toThrow();
    expect(() => canonicalizeStrict({ a: 1.5 })).toThrow();
    expect(() => canonicalizeStrict({ a: "\uD800" })).toThrow();
    const sparse = Array.from({ length: 2 }) as unknown[];
    delete sparse[0];
    sparse[1] = 1;
    expect(() => canonicalizeStrict({ a: sparse as never })).toThrow();
    expect(() => parseJsonStrict('{"a":1,"a":2}')).toThrow();
    expect(() => parseJsonStrict('{"a":1e0}')).toThrow();
    expect(() => parseJsonStrict('{"a":-0}')).toThrow();
    expect(() => parseJsonStrict('{"a":"\\uD800"}')).toThrow();
    expect(() => parseJsonStrict('{"a":null}')).toThrow();
    expect(() => parseJsonStrictBytes(new Uint8Array([0xff]))).toThrow();
  });
});
