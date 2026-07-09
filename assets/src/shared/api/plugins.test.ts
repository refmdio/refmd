import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const getMock = vi.fn();
const postMock = vi.fn();
const patchMock = vi.fn();
const deleteMock = vi.fn();

vi.mock("./core", () => ({
  client: {
    GET: getMock,
    POST: postMock,
    PATCH: patchMock,
    DELETE: deleteMock,
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

describe("pluginsApi", () => {
  beforeEach(() => {
    getMock.mockReset();
    postMock.mockReset();
    patchMock.mockReset();
    deleteMock.mockReset();
  });

  it("routes personal candidates through the user-owned package endpoint", async () => {
    postMock.mockResolvedValue({
      data: {
        candidate: {
          id: "candidate-one",
          owner_scope_kind: "user",
          source_kind: "remote_https_url",
        },
      },
      response: new Response(),
    });
    const { pluginsApi } = await import("./plugins");

    await pluginsApi.createCandidate({
      ownerScopeKind: "user",
      sourceKind: "remote_https_url",
      sourceUrl: "https://example.com/plugin.zip",
    });

    expect(postMock).toHaveBeenCalledWith(
      "/api/plugin-packages",
      expect.objectContaining({
        body: {
          source_kind: "remote_https_url",
          source_url: "https://example.com/plugin.zip",
        },
      }),
    );
  });

  it("keeps explicit personal selection on the user-owned endpoint even with workspace context", async () => {
    postMock.mockResolvedValue({
      data: {
        candidate: {
          id: "candidate-dual-user",
          owner_scope_kind: "user",
          source_kind: "local_upload",
        },
      },
      response: new Response(),
    });
    const { pluginsApi } = await import("./plugins");

    await pluginsApi.createCandidate({
      ownerScopeKind: "user",
      workspaceId: "workspace-one",
      sourceKind: "local_upload",
      archiveBase64: "YXJjaGl2ZQ==",
    });

    expect(postMock).toHaveBeenCalledWith(
      "/api/plugin-packages",
      expect.objectContaining({
        body: {
          source_kind: "local_upload",
          archive_base64: "YXJjaGl2ZQ==",
        },
      }),
    );
  });

  it("creates initial candidates through the manifest-routed endpoint", async () => {
    postMock.mockResolvedValue({
      data: {
        candidate: {
          id: "candidate-routed",
          owner_scope_kind: "user",
          source_kind: "remote_https_url",
          scope_summary: {
            supported_owner_scopes: ["user"],
            default_owner_scope: "user",
            workspace_application: "none",
          },
          approval_summary: {
            approval_event_hash: "approval-one",
            approval_epoch: 1,
            previous_approval_event_hash: "GENESIS",
            created_at_ms: 1,
            actor: { device_id: "device-one" },
            subject: { owner_scope_kind: "user" },
          },
        },
      },
      response: new Response(),
    });
    const { pluginsApi } = await import("./plugins");

    const candidate = await pluginsApi.createCandidate({
      workspaceId: "workspace-one",
      sourceKind: "remote_https_url",
      sourceUrl: "https://example.com/plugin.zip",
    });

    expect(candidate.scope_summary?.supported_owner_scopes).toEqual(["user"]);
    expect(candidate.approval_summary?.approval_event_hash).toBe("approval-one");
    expect(postMock).toHaveBeenCalledWith(
      "/api/plugin-candidates",
      expect.objectContaining({
        body: {
          source_kind: "remote_https_url",
          source_url: "https://example.com/plugin.zip",
          workspace_id: "workspace-one",
        },
      }),
    );
  });

  it("routes workspace candidates through the workspace package endpoint", async () => {
    postMock.mockResolvedValue({
      data: {
        candidate: {
          id: "candidate-two",
          owner_scope_kind: "workspace",
          source_kind: "local_upload",
        },
      },
      response: new Response(),
    });
    const { pluginsApi } = await import("./plugins");

    await pluginsApi.createCandidate({
      ownerScopeKind: "workspace",
      workspaceId: "workspace-one",
      sourceKind: "local_upload",
      archiveBase64: "YXJjaGl2ZQ==",
    });

    expect(postMock).toHaveBeenCalledWith(
      "/api/workspaces/{workspace_id}/plugin-packages",
      expect.objectContaining({
        params: expect.objectContaining({
          path: { workspace_id: "workspace-one" },
        }),
        body: {
          source_kind: "local_upload",
          archive_base64: "YXJjaGl2ZQ==",
        },
      }),
    );
  });

  it("uses the candidate resource endpoint for summary and approval", async () => {
    getMock.mockResolvedValue({
      data: { candidate: { id: "candidate-one", owner_scope_kind: "workspace" } },
      response: new Response(),
    });
    postMock.mockResolvedValue({
      data: {
        package: { id: "package-one", plugin_id: "plugin-one" },
        application: { id: "application-one", package_id: "package-one" },
        activation: { id: "activation-one", application_id: "application-one" },
      },
      response: new Response(),
    });
    const { pluginsApi } = await import("./plugins");

    await pluginsApi.showCandidate("workspace", "candidate-one", "workspace-one");
    const promotion = await pluginsApi.promoteCandidate(
      "workspace",
      "candidate-one",
      {
        approval_event_hash: "approval-one",
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS",
        created_at_ms: 1,
        hybrid_signature: {},
      },
      "workspace-one",
    );

    expect(getMock).toHaveBeenCalledWith(
      "/api/plugin-candidates/{candidate_id}",
      expect.objectContaining({
        params: expect.objectContaining({ path: { candidate_id: "candidate-one" } }),
      }),
    );
    expect(postMock).toHaveBeenCalledWith(
      "/api/plugin-candidates/{candidate_id}/approval",
      expect.objectContaining({
        params: expect.objectContaining({ path: { candidate_id: "candidate-one" } }),
        body: expect.objectContaining({ workspace_id: "workspace-one" }),
      }),
    );
    expect(promotion).toEqual({
      package: { id: "package-one", plugin_id: "plugin-one" },
      application: { id: "application-one", package_id: "package-one" },
      activation: { id: "activation-one", application_id: "application-one" },
    });
  });

  it("applies, updates, and deletes workspace applications through plugin management routes", async () => {
    postMock.mockResolvedValue({
      data: { application: { id: "application-one" } },
      response: new Response(),
    });
    patchMock.mockResolvedValue({
      data: { plugin: { id: "application-one", enabled: false } },
      response: new Response(),
    });
    deleteMock.mockResolvedValue({
      data: { plugin: { id: "application-one" } },
      response: new Response(),
    });
    const { pluginsApi } = await import("./plugins");

    await pluginsApi.applyPackage("workspace-one", "package-one");
    await pluginsApi.updateApplication("workspace-one", "application-one", { enabled: false });
    await pluginsApi.deleteApplication("workspace-one", "application-one");

    expect(postMock).toHaveBeenCalledWith(
      "/api/workspaces/{workspace_id}/plugin-applications",
      expect.objectContaining({
        params: expect.objectContaining({ path: { workspace_id: "workspace-one" } }),
        body: { package_id: "package-one" },
      }),
    );
    expect(patchMock).toHaveBeenCalledWith(
      "/api/workspaces/{workspace_id}/plugin-applications/{application_id}",
      expect.objectContaining({
        params: expect.objectContaining({
          path: { workspace_id: "workspace-one", application_id: "application-one" },
        }),
        body: { enabled: false },
      }),
    );
    expect(deleteMock).toHaveBeenCalledWith(
      "/api/workspaces/{workspace_id}/plugin-applications/{application_id}",
      expect.objectContaining({
        params: expect.objectContaining({
          path: { workspace_id: "workspace-one", application_id: "application-one" },
        }),
      }),
    );
  });
});
