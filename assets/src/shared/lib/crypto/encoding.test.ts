import { describe, expect, it } from "vite-plus/test";
import { assertBase64Url, decodeBase64UrlStrict, encodeBase64Url } from "./encoding";

describe("strict base64url encoding", () => {
  it("accepts only canonical unpadded base64url", () => {
    const encoded = encodeBase64Url(new Uint8Array([102, 111, 111]));
    expect(encoded).toBe("Zm9v");
    expect(decodeBase64UrlStrict(encoded, 3)).toEqual(new Uint8Array([102, 111, 111]));
    expect(() => assertBase64Url("Zg==")).toThrow();
    expect(() => assertBase64Url("Zm8/")).toThrow();
    expect(() => assertBase64Url("A")).toThrow();
  });
});
