import { describe, expect, it } from "vitest";
import { buildInvitationExpiryIso, buildInvitationLink } from "./utils";

describe("invitation-utils", () => {
  it("builds an invitation link with the token fragment", () => {
    expect(buildInvitationLink("https://example.com", "abc123")).toBe(
      "https://example.com/invite#token=abc123",
    );
  });

  it("builds an expiration timestamp from a fixed reference time", () => {
    expect(buildInvitationExpiryIso(7, Date.UTC(2026, 2, 31, 0, 0, 0))).toBe(
      "2026-04-07T00:00:00.000Z",
    );
  });
});
