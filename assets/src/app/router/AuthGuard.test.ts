import { describe, expect, it } from "vite-plus/test";
import { retainLogoutIncomplete, secureLogoutRedirect } from "./AuthGuard";

describe("auth guard redirect state", () => {
  it("retains an incomplete logout marker across auth redirects", () => {
    expect(retainLogoutIncomplete("/dashboard", "?logout_incomplete=true")).toBe(
      "/dashboard?logout_incomplete=true",
    );
    expect(retainLogoutIncomplete("/devices/register", "?logout_incomplete=true")).toBe(
      "/devices/register?logout_incomplete=true",
    );
  });

  it("does not forward unrelated or false query values", () => {
    expect(retainLogoutIncomplete("/dashboard", "?settings=account")).toBe("/dashboard");
    expect(retainLogoutIncomplete("/dashboard", "?logout_incomplete=false")).toBe("/dashboard");
  });

  it.each(["/auth/register", "/auth/recovery", "/auth/password-reset", "/devices/register"])(
    "blocks authentication entry route %s until secure cleanup completes",
    (path) => {
      expect(secureLogoutRedirect(path, true)).toBe("/auth/login?logout_incomplete=true");
    },
  );

  it("allows only the cleanup login route while secure cleanup is incomplete", () => {
    expect(secureLogoutRedirect("/auth/login", true)).toBeNull();
    expect(secureLogoutRedirect("/auth/register", false)).toBeNull();
  });
});
