import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const postMock = vi.fn();
const withUserRrpParamsMock = vi.fn((params: Record<string, unknown> = {}) => ({
  ...params,
  header: {
    "x-refmd-rrp-actor-variant": "user_device",
    "x-refmd-rrp-device-id": "",
    "x-refmd-rrp-challenge": "",
    "x-refmd-rrp-signature-transport": "",
  },
}));

vi.mock("./core", () => ({
  client: {
    POST: postMock,
  },
  throwIfError: (result: { data?: unknown; error?: unknown }) => {
    if (result.error) throw new Error("api_error");
    return result.data;
  },
  withUserRrpParams: withUserRrpParamsMock,
}));

describe("devicesApi", () => {
  beforeEach(() => {
    postMock.mockReset();
    withUserRrpParamsMock.mockClear();
  });

  it("uses user RRP params for normal approval", async () => {
    postMock.mockResolvedValue({ data: { device: { id: "device-1" } }, response: new Response() });
    const { devicesApi } = await import("./devices");

    await devicesApi.approve("device-1", {} as Parameters<typeof devicesApi.approve>[1]);

    expect(withUserRrpParamsMock).toHaveBeenCalledWith({ path: { device_id: "device-1" } });
    expect(postMock).toHaveBeenCalledWith(
      "/api/devices/registrations/{device_id}/approve",
      expect.objectContaining({
        params: expect.objectContaining({
          path: { device_id: "device-1" },
          header: expect.objectContaining({
            "x-refmd-rrp-device-id": "",
            "x-refmd-rrp-challenge": "",
            "x-refmd-rrp-signature-transport": "",
          }),
        }),
      }),
    );
  });

  it("does not send empty RRP params for recovery approval", async () => {
    postMock.mockResolvedValue({ data: { device: { id: "device-2" } }, response: new Response() });
    const { devicesApi } = await import("./devices");

    await devicesApi.approveRecovered(
      "device-2",
      {} as Parameters<typeof devicesApi.approveRecovered>[1],
    );

    expect(withUserRrpParamsMock).not.toHaveBeenCalled();
    expect(postMock).toHaveBeenCalledWith(
      "/api/devices/registrations/{device_id}/approve",
      expect.objectContaining({
        params: { path: { device_id: "device-2" } },
      }),
    );
  });
});
