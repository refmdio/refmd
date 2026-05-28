import { beforeEach, describe, expect, it, vi } from "vitest";

const postMock = vi.fn();
const withUserPopParamsMock = vi.fn((params: Record<string, unknown> = {}) => ({
  ...params,
  header: {
    "x-pop-actor-variant": "user_device",
    "x-pop-device-id": "",
    "x-pop-challenge": "",
    "x-pop-signature-transport": "",
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
  withUserPopParams: withUserPopParamsMock,
}));

describe("devicesApi", () => {
  beforeEach(() => {
    postMock.mockReset();
    withUserPopParamsMock.mockClear();
  });

  it("uses user PoP params for normal approval", async () => {
    postMock.mockResolvedValue({ data: { device: { id: "device-1" } }, response: new Response() });
    const { devicesApi } = await import("./devices");

    await devicesApi.approve("device-1", {} as Parameters<typeof devicesApi.approve>[1]);

    expect(withUserPopParamsMock).toHaveBeenCalledWith({ path: { device_id: "device-1" } });
    expect(postMock).toHaveBeenCalledWith(
      "/api/devices/registrations/{device_id}/approve",
      expect.objectContaining({
        params: expect.objectContaining({
          path: { device_id: "device-1" },
          header: expect.objectContaining({
            "x-pop-device-id": "",
            "x-pop-challenge": "",
            "x-pop-signature-transport": "",
          }),
        }),
      }),
    );
  });

  it("does not send empty PoP params for recovery approval", async () => {
    postMock.mockResolvedValue({ data: { device: { id: "device-2" } }, response: new Response() });
    const { devicesApi } = await import("./devices");

    await devicesApi.approveRecovered(
      "device-2",
      {} as Parameters<typeof devicesApi.approveRecovered>[1],
    );

    expect(withUserPopParamsMock).not.toHaveBeenCalled();
    expect(postMock).toHaveBeenCalledWith(
      "/api/devices/registrations/{device_id}/approve",
      expect.objectContaining({
        params: { path: { device_id: "device-2" } },
      }),
    );
  });
});
