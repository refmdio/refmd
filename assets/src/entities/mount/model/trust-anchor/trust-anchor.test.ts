import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  deviceState: vi.fn(),
  loadStoredDsk: vi.fn(),
  storeMountTrustAnchorWithDsk: vi.fn(),
  loadMountTrustAnchorWithDsk: vi.fn(),
  deleteMountTrustAnchorWithDsk: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    loadStoredDsk: mocks.loadStoredDsk,
    storeMountTrustAnchorWithDsk: mocks.storeMountTrustAnchorWithDsk,
    loadMountTrustAnchorWithDsk: mocks.loadMountTrustAnchorWithDsk,
    deleteMountTrustAnchorWithDsk: mocks.deleteMountTrustAnchorWithDsk,
  }),
}));

import {
  loadMountTrustAnchor,
  mountTrustAnchorRequest,
  mountTargetTokenHash,
  rememberMountTrustAnchor,
} from "./trust-anchor";

describe("MountTrustAnchor", () => {
  const targetToken = "dGFyZ2V0LXRva2Vu";
  const workspacePinBootstrapHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  beforeEach(() => {
    vi.clearAllMocks();
    mocks.authState.mockReturnValue({ user: { id: "user-1" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-1" });
    mocks.loadStoredDsk.mockResolvedValue(true);
  });

  it("stores a minimal canonical anchor without free-form secret refs", async () => {
    await rememberMountTrustAnchor({
      mountId: "mount-1",
      shareId: "share-1",
      shareSessionKey: "mount:mount-1",
      targetToken,
      targetKind: "document",
      targetTitle: "Shared document",
      workspacePinBootstrapHash,
    });

    expect(mocks.storeMountTrustAnchorWithDsk).toHaveBeenCalledTimes(1);
    const stored = mocks.storeMountTrustAnchorWithDsk.mock.calls[0][0];
    expect(stored.mountId).toBe("mount-1");
    expect(Object.keys(stored.aadRecord).sort()).toEqual([
      "authenticated_source_kind",
      "created_at_ms",
      "mount_id",
      "mount_owner_device_id",
      "mount_owner_user_id",
      "protocol",
      "share_id",
      "share_session_key",
      "target_kind",
      "target_token_hash",
      "version",
      "workspace_pin_bootstrap_hash",
    ]);
    expect(stored.aadRecord).not.toHaveProperty("capability_reopen_secret_ref");
    expect(stored.aadRecord).not.toHaveProperty("password_capability_secret_ref");

    const record = JSON.parse(new TextDecoder().decode(stored.plaintext));
    expect(record).toEqual({
      protocol: "refmd.mount-trust-anchor",
      version: 1,
      mount_id: "mount-1",
      share_id: "share-1",
      target_kind: "document",
      target_token_hash: mountTargetTokenHash(targetToken),
      workspace_pin_bootstrap_hash: workspacePinBootstrapHash,
      share_session_key: "mount:mount-1",
      authenticated_source_kind: "url-fragment",
      mount_owner_user_id: "user-1",
      mount_owner_device_id: "device-1",
      created_at_ms: record.created_at_ms,
      target_title: "Shared document",
    });
    expect(record).not.toHaveProperty("capability_reopen_secret_ref");
    expect(record).not.toHaveProperty("password_capability_secret_ref");
  });

  it("loads only anchors bound to the expected mount, share, target, and owner device", async () => {
    const record = {
      protocol: "refmd.mount-trust-anchor",
      version: 1,
      mount_id: "mount-1",
      share_id: "share-1",
      target_kind: "folder",
      target_token_hash: mountTargetTokenHash(targetToken),
      workspace_pin_bootstrap_hash: workspacePinBootstrapHash,
      share_session_key: "mount:mount-1",
      authenticated_source_kind: "url-fragment",
      mount_owner_user_id: "user-1",
      mount_owner_device_id: "device-1",
      created_at_ms: 1,
      target_title: "",
    };
    mocks.loadMountTrustAnchorWithDsk.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(record)),
    );

    await expect(loadMountTrustAnchor("mount-1", "share-1", targetToken)).resolves.toMatchObject({
      mountId: "mount-1",
      shareId: "share-1",
      targetKind: "folder",
      shareSessionKey: "mount:mount-1",
      workspacePinBootstrapHash,
    });

    await expect(loadMountTrustAnchor("mount-1", "other-share", targetToken)).resolves.toBeNull();
    await expect(
      loadMountTrustAnchor("mount-1", "share-1", "b3RoZXItdGFyZ2V0"),
    ).resolves.toBeNull();

    mocks.deviceState.mockReturnValue({ deviceId: "device-2" });
    await expect(loadMountTrustAnchor("mount-1", "share-1", targetToken)).resolves.toBeNull();
  });

  it("rejects anchors whose session key is not deterministically derived from the mount id", async () => {
    const record = {
      protocol: "refmd.mount-trust-anchor",
      version: 1,
      mount_id: "mount-1",
      share_id: "share-1",
      target_kind: "document",
      target_token_hash: mountTargetTokenHash(targetToken),
      workspace_pin_bootstrap_hash: workspacePinBootstrapHash,
      share_session_key: "mount:other-mount",
      authenticated_source_kind: "url-fragment",
      mount_owner_user_id: "user-1",
      mount_owner_device_id: "device-1",
      created_at_ms: 1,
      target_title: "",
    };
    mocks.loadMountTrustAnchorWithDsk.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(record)),
    );

    await expect(loadMountTrustAnchor("mount-1", "share-1", targetToken)).resolves.toBeNull();
  });

  it("builds mount bootstrap requests only from a complete local trust anchor", () => {
    const anchor = {
      mountId: "mount-1",
      shareId: "share-1",
      targetKind: "document" as const,
      shareSessionKey: "mount:mount-1",
      targetTokenHash: mountTargetTokenHash(targetToken),
      workspacePinBootstrapHash,
      targetTitle: null,
      userId: "user-1",
      deviceId: "device-1",
      createdAtMs: 1,
    };

    expect(mountTrustAnchorRequest(anchor)).toEqual({
      authenticatedWorkspacePinBootstrapHash: workspacePinBootstrapHash,
    });

    expect(() =>
      mountTrustAnchorRequest({
        ...anchor,
        shareSessionKey: "mount:other-mount",
      }),
    ).toThrow("mount_trust_anchor_session_key_invalid");

    expect(() =>
      mountTrustAnchorRequest({
        ...anchor,
        serverSuppliedHash: workspacePinBootstrapHash,
      } as typeof anchor),
    ).toThrow("mount_trust_anchor_invalid");
  });
});
