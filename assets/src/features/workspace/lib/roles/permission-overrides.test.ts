import { describe, expect, it } from "vitest";
import {
  buildRolePermissions,
  getPermissionOverrideState,
  togglePermissionOverride,
} from "./permission-overrides";

describe("permission-overrides", () => {
  it("cycles permission overrides through granted, denied, and default", () => {
    const granted = togglePermissionOverride({}, "member:invite");
    expect(granted).toEqual({ "member:invite": true });

    const denied = togglePermissionOverride(granted, "member:invite");
    expect(denied).toEqual({ "member:invite": false });

    const reset = togglePermissionOverride(denied, "member:invite");
    expect(reset).toEqual({});
  });

  it("reports the current permission override state", () => {
    expect(getPermissionOverrideState({}, "member:invite")).toBe("default");
    expect(getPermissionOverrideState({ "member:invite": true }, "member:invite")).toBe("granted");
    expect(getPermissionOverrideState({ "member:invite": false }, "member:invite")).toBe("denied");
  });

  it("builds the payload with only explicitly changed overrides", () => {
    expect(
      buildRolePermissions({
        "workspace:update": false,
      }),
    ).toEqual([{ permission: "workspace:update", granted: false }]);
  });

  it("excludes null (default) entries from the payload", () => {
    expect(
      buildRolePermissions({
        "workspace:update": false,
        "member:invite": null,
      }),
    ).toEqual([{ permission: "workspace:update", granted: false }]);
  });
});
