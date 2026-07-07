import { describe, expect, it } from "vite-plus/test";
import { actionRequiredSecurityNotificationCount } from "./pending-monitor";

describe("actionRequiredSecurityNotificationCount", () => {
  it("counts unhandled action-required security notifications", () => {
    expect(
      actionRequiredSecurityNotificationCount(
        [
          {
            id: "one",
            type: "plugin.consent_required",
            severity: "action_required",
          },
          {
            id: "two",
            type: "device.pending_approval",
            severity: "action_required",
            acted_at: "2026-05-24T00:00:00Z",
          },
          {
            id: "three",
            type: "workspace.kek_rotation_needed",
            severity: "action_required",
            expires_at: "2026-05-24T00:00:00Z",
          },
          {
            id: "four",
            type: "plugin.runtime_updated",
            severity: "warning",
          },
        ],
        new Date("2026-05-24T01:00:00Z").getTime(),
      ),
    ).toBe(1);
  });
});
