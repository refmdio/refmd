import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { verifyAndPinAuditCheckpoint, type GenesisAuditAuthority } from "./audit-checkpoint-pin";

interface SetupAuditCheckpoints {
  user_audit_checkpoint: unknown;
  workspace_audit_checkpoints: Array<{
    workspace_id: string;
    audit_checkpoint: unknown;
  }>;
}

export async function verifyAndPinSetupAuditCheckpoints(params: {
  userId: string;
  rrpDeviceId: string;
  checkpoints: SetupAuditCheckpoints;
  genesisAuthority: GenesisAuditAuthority;
}): Promise<void> {
  await Promise.all([
    fetchVerifiedKeyDirectory({
      scopeKind: "user",
      scopeId: params.userId,
      rrpDeviceId: params.rrpDeviceId,
    }),
    ...params.checkpoints.workspace_audit_checkpoints.map((entry) =>
      fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: entry.workspace_id,
        rrpDeviceId: params.rrpDeviceId,
      }),
    ),
  ]);

  await verifyAndPinAuditCheckpoint(params.checkpoints.user_audit_checkpoint, {
    genesisAuthority: params.genesisAuthority,
  });
  await Promise.all(
    params.checkpoints.workspace_audit_checkpoints.map((entry) =>
      verifyAndPinAuditCheckpoint(entry.audit_checkpoint, {
        genesisAuthority: params.genesisAuthority,
      }),
    ),
  );
}
