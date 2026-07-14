import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const getMock = vi.fn();
const patchMock = vi.fn();
const verifyAndPinAuditCheckpoint = vi.fn(async (_checkpoint: unknown): Promise<void> => undefined);

vi.mock("@/shared/lib/anti-rollback/audit-checkpoint-pin", () => ({
  verifyAndPinAuditCheckpoint,
}));

vi.mock("./core", () => ({
  client: {
    GET: getMock,
    PATCH: patchMock,
  },
  throwIfError: (result: { data?: unknown; error?: unknown }) => {
    if (result.error) throw new Error("api_error");
    return result.data;
  },
  withUserRrpParams: (params: Record<string, unknown> = {}) => ({
    ...params,
    header: {
      "x-refmd-rrp-actor-variant": "user_device",
      "x-refmd-rrp-device-id": "",
      "x-refmd-rrp-challenge": "",
      "x-refmd-rrp-signature-transport": "",
    },
  }),
}));

describe("securityNotificationsApi", () => {
  beforeEach(() => {
    getMock.mockReset();
    patchMock.mockReset();
    verifyAndPinAuditCheckpoint.mockReset();
    verifyAndPinAuditCheckpoint.mockImplementation(async (checkpoint: unknown) => {
      if (checkpoint === undefined) throw new Error("audit_checkpoint_missing");
    });
  });

  it("lists user notifications", async () => {
    getMock.mockResolvedValue({
      data: {
        notifications: [
          {
            id: "notification-one",
            severity: "action_required",
            audit_checkpoint: { chain_scope: "user:user-one" },
          },
        ],
      },
      response: new Response(),
    });
    const { securityNotificationsApi } = await import("./security-notifications");

    await expect(securityNotificationsApi.list()).resolves.toEqual([
      {
        id: "notification-one",
        severity: "action_required",
        audit_checkpoint: { chain_scope: "user:user-one" },
      },
    ]);
    expect(verifyAndPinAuditCheckpoint).toHaveBeenCalledWith({
      chain_scope: "user:user-one",
    });
    expect(getMock).toHaveBeenCalledWith(
      "/api/security/notifications",
      expect.objectContaining({ params: expect.any(Object) }),
    );
  });

  it("marks notifications read and dismissed through server-side state endpoints", async () => {
    patchMock.mockResolvedValue({
      data: {
        notification: {
          id: "notification-one",
          read_at: "2026-05-31T00:00:00Z",
          audit_checkpoint: { chain_scope: "user:user-one" },
        },
      },
      response: new Response(),
    });
    const { securityNotificationsApi } = await import("./security-notifications");

    await expect(securityNotificationsApi.markRead("notification-one")).resolves.toMatchObject({
      id: "notification-one",
      read_at: "2026-05-31T00:00:00Z",
    });
    expect(patchMock).toHaveBeenCalledWith(
      "/api/security/notifications/{notification_id}/read",
      expect.objectContaining({
        params: expect.objectContaining({ path: { notification_id: "notification-one" } }),
      }),
    );

    patchMock.mockResolvedValue({
      data: {
        notification: {
          id: "notification-one",
          dismissed_at: "2026-05-31T00:01:00Z",
          audit_checkpoint: { chain_scope: "user:user-one" },
        },
      },
      response: new Response(),
    });
    await expect(securityNotificationsApi.dismiss("notification-one")).resolves.toMatchObject({
      id: "notification-one",
      dismissed_at: "2026-05-31T00:01:00Z",
    });
    expect(patchMock).toHaveBeenCalledWith(
      "/api/security/notifications/{notification_id}/dismiss",
      expect.objectContaining({
        params: expect.objectContaining({ path: { notification_id: "notification-one" } }),
      }),
    );
  });

  it("rejects a notification response without an audit checkpoint", async () => {
    getMock.mockResolvedValue({
      data: {
        notifications: [{ id: "notification-one", severity: "warning" }],
      },
      response: new Response(),
    });
    const { securityNotificationsApi } = await import("./security-notifications");

    await expect(securityNotificationsApi.list()).rejects.toThrow("audit_checkpoint_missing");
  });
});
