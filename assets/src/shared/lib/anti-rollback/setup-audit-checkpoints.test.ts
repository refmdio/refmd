import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const calls: string[] = [];
const fetchVerifiedKeyDirectory = vi.fn(async (params: { scopeKind: string; scopeId: string }) => {
  calls.push(`fetch:${params.scopeKind}:${params.scopeId}`);
  return { checkpoint: {} };
});
const verifyAndPinAuditCheckpoint = vi.fn(async (checkpoint: { id: string }) => {
  calls.push(`pin:${checkpoint.id}`);
});

vi.mock("@/shared/lib/key-directory/fetch", () => ({ fetchVerifiedKeyDirectory }));
vi.mock("./audit-checkpoint-pin", () => ({ verifyAndPinAuditCheckpoint }));

describe("setup audit checkpoints", () => {
  beforeEach(() => {
    calls.length = 0;
    fetchVerifiedKeyDirectory.mockClear();
    verifyAndPinAuditCheckpoint.mockClear();
  });

  it("verifies every authority lineage before pinning any audit checkpoint", async () => {
    const { verifyAndPinSetupAuditCheckpoints } = await import("./setup-audit-checkpoints");

    await verifyAndPinSetupAuditCheckpoints({
      userId: "user-one",
      rrpDeviceId: "device-one",
      checkpoints: {
        user_audit_checkpoint: { id: "user-audit" },
        workspace_audit_checkpoints: [
          { workspace_id: "workspace-one", audit_checkpoint: { id: "workspace-audit-one" } },
          { workspace_id: "workspace-two", audit_checkpoint: { id: "workspace-audit-two" } },
        ],
      },
    });

    expect(calls).toEqual([
      "fetch:user:user-one",
      "fetch:workspace:workspace-one",
      "fetch:workspace:workspace-two",
      "pin:user-audit",
      "pin:workspace-audit-one",
      "pin:workspace-audit-two",
    ]);
    expect(fetchVerifiedKeyDirectory).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: "workspace-one",
      rrpDeviceId: "device-one",
    });
  });

  it("does not pin audit state when authority lineage verification fails", async () => {
    fetchVerifiedKeyDirectory.mockRejectedValueOnce(new Error("key_directory_fetch_failed"));
    const { verifyAndPinSetupAuditCheckpoints } = await import("./setup-audit-checkpoints");

    await expect(
      verifyAndPinSetupAuditCheckpoints({
        userId: "user-one",
        rrpDeviceId: "device-one",
        checkpoints: {
          user_audit_checkpoint: { id: "user-audit" },
          workspace_audit_checkpoints: [],
        },
      }),
    ).rejects.toThrow("key_directory_fetch_failed");
    expect(verifyAndPinAuditCheckpoint).not.toHaveBeenCalled();
  });
});
