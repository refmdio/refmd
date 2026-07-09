import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  post: vi.fn(),
  withUserRrpParams: vi.fn((params: Record<string, unknown> = {}) => ({
    ...params,
    header: {
      "x-refmd-rrp-actor-variant": "user_device",
      "x-refmd-rrp-device-id": "",
      "x-refmd-rrp-challenge": "",
      "x-refmd-rrp-signature-transport": "",
    },
  })),
}));

vi.mock("./core", () => ({
  client: {
    POST: mocks.post,
  },
  RRP_DEVICE_OVERRIDE_HEADER: "X-RefMD-RRP-Override-Device-Id",
  throwIfError: (result: { data?: unknown; error?: unknown }) => {
    if (result.error) throw new Error("api_error");
    return result.data;
  },
  withUserRrpParams: mocks.withUserRrpParams,
}));

import { encryptionApi } from "./encryption";

describe("encryptionApi", () => {
  beforeEach(() => {
    mocks.post.mockReset();
    mocks.withUserRrpParams.mockClear();
  });

  it("forwards the RRP device override when saving member envelopes", async () => {
    mocks.post.mockResolvedValue({ data: {}, response: new Response() });
    const body = {
      envelopes: [],
      workspace_key_directory_events: [],
      workspace_key_directory_checkpoint: { payload: {} },
    } as unknown as Parameters<typeof encryptionApi.saveMemberEnvelopes>[1];

    await encryptionApi.saveMemberEnvelopes("workspace-one", body, {
      rrpDeviceId: "device-override",
    });

    expect(mocks.withUserRrpParams).toHaveBeenCalledWith({
      path: { workspace_id: "workspace-one" },
    });
    expect(mocks.post).toHaveBeenCalledWith(
      "/api/encryption/workspaces/{workspace_id}/member-envelopes",
      expect.objectContaining({
        body,
        headers: {
          "X-RefMD-RRP-Override-Device-Id": "device-override",
        },
        params: expect.objectContaining({
          path: { workspace_id: "workspace-one" },
        }),
      }),
    );
  });
});
