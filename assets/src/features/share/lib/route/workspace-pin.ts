import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import {
  verifyAndInstallWorkspacePinBootstrap,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";

export async function ensureShareWorkspaceKeyDirectoryPin(params: {
  workspaceId: string;
  workspacePinBootstrapHash?: string | null;
  workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
  workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
  mismatchCode: string;
}): Promise<void> {
  if (await getKeyDirectoryPin("workspace", params.workspaceId)) return;

  if (
    !params.workspacePinBootstrapHash ||
    !params.workspacePinBootstrap ||
    !params.workspaceKeyDirectoryCheckpoint
  ) {
    throw new Error(params.mismatchCode);
  }

  try {
    await verifyAndInstallWorkspacePinBootstrap({
      workspaceId: params.workspaceId,
      authenticatedWorkspacePinBootstrapHash: params.workspacePinBootstrapHash,
      bootstrap: params.workspacePinBootstrap,
      checkpointEnvelope: params.workspaceKeyDirectoryCheckpoint,
      operationSequence: checkpointEventHeadSequence(params.workspaceKeyDirectoryCheckpoint),
    });
  } catch {
    throw new Error(params.mismatchCode);
  }
}

function checkpointEventHeadSequence(checkpointEnvelope: KeyDirectoryEnvelope): number {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const head = payload?.covered_event_head as Record<string, unknown> | undefined;
  const sequence = head?.head_sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error("workspace_key_directory_checkpoint_head_invalid");
  }
  return sequence;
}
