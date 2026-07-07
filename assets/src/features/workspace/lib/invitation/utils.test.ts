import { describe, expect, it } from "vite-plus/test";
import { buildInvitationExpiryIso, buildInvitationLink } from "@/shared/lib/invite/link";

describe("invitation-utils", () => {
  it("builds an invitation link with the token fragment", () => {
    expect(buildInvitationLink("https://example.com", "lookup123.bootstrap456")).toBe(
      "https://example.com/invite#it=lookup123&ib=bootstrap456",
    );
  });

  it("builds an expiration timestamp from a fixed reference time", () => {
    expect(buildInvitationExpiryIso(7, Date.UTC(2026, 2, 31, 0, 0, 0))).toBe(
      "2026-04-07T00:00:00.000Z",
    );
  });
});
