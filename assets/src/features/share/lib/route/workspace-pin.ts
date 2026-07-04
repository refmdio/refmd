import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import {
  verifyAndInstallWorkspacePinBootstrap,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";

function recordSharePinPerf(event: string, detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  const payload = {
    event,
    detail,
    at: Date.now(),
    now: performance.now(),
  };
  const target = window as Window & { __refmdE2ESyncPerf?: unknown[] };
  target.__refmdE2ESyncPerf ??= [];
  target.__refmdE2ESyncPerf.push(payload);
  window.dispatchEvent(new CustomEvent("refmd:sync-perf", { detail: payload }));
}

const pendingWorkspacePinInstalls = new Map<string, Promise<void>>();

function pendingWorkspacePinKey(params: {
  workspaceId: string;
  workspacePinBootstrapHash: string;
}): string {
  return `${params.workspaceId}:${params.workspacePinBootstrapHash}`;
}

export async function ensureShareWorkspaceKeyDirectoryPin(params: {
  workspaceId: string;
  workspacePinBootstrapHash?: string | null;
  workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
  workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
  workspaceKeyDirectoryLatestCheckpoint?: KeyDirectoryEnvelope | null;
  workspaceKeyDirectoryCheckpointAncestry?: KeyDirectoryEnvelope[];
  workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
  mismatchCode: string;
}): Promise<void> {
  const startedAt = performance.now();
  recordSharePinPerf("share_workspace_pin_check_start", {
    workspaceId: params.workspaceId,
  });
  if (await getKeyDirectoryPin("workspace", params.workspaceId)) {
    await verifyShareWorkspaceKeyDirectoryLineage(params, startedAt);
    recordSharePinPerf("share_workspace_pin_check_ready", {
      workspaceId: params.workspaceId,
      elapsedMs: performance.now() - startedAt,
      existing: true,
    });
    return;
  }
  recordSharePinPerf("share_workspace_pin_check_ready", {
    workspaceId: params.workspaceId,
    elapsedMs: performance.now() - startedAt,
    existing: false,
  });

  if (
    !params.workspacePinBootstrapHash ||
    !params.workspacePinBootstrap ||
    !params.workspaceKeyDirectoryCheckpoint
  ) {
    throw new Error(params.mismatchCode);
  }
  const workspacePinBootstrapHash = params.workspacePinBootstrapHash;
  const workspacePinBootstrap = params.workspacePinBootstrap;
  const workspaceKeyDirectoryCheckpoint = params.workspaceKeyDirectoryCheckpoint;

  const pendingKey = pendingWorkspacePinKey({
    workspaceId: params.workspaceId,
    workspacePinBootstrapHash,
  });
  const pending = pendingWorkspacePinInstalls.get(pendingKey);
  if (pending) {
    await pending;
    recordSharePinPerf("share_workspace_pin_verify_ready", {
      workspaceId: params.workspaceId,
      elapsedMs: performance.now() - startedAt,
      source: "pending",
    });
    return;
  }

  const verify = (async () => {
    try {
      recordSharePinPerf("share_workspace_pin_verify_start", {
        workspaceId: params.workspaceId,
        elapsedMs: performance.now() - startedAt,
      });
      await verifyAndInstallWorkspacePinBootstrap({
        workspaceId: params.workspaceId,
        authenticatedWorkspacePinBootstrapHash: workspacePinBootstrapHash,
        bootstrap: workspacePinBootstrap,
        checkpointEnvelope: workspaceKeyDirectoryCheckpoint,
        operationSequence: checkpointEventHeadSequence(workspaceKeyDirectoryCheckpoint),
      });
      await verifyShareWorkspaceKeyDirectoryLineage(params, startedAt);
      recordSharePinPerf("share_workspace_pin_verify_ready", {
        workspaceId: params.workspaceId,
        elapsedMs: performance.now() - startedAt,
      });
    } catch {
      throw new Error(params.mismatchCode);
    }
  })().finally(() => {
    if (pendingWorkspacePinInstalls.get(pendingKey) === verify) {
      pendingWorkspacePinInstalls.delete(pendingKey);
    }
  });
  pendingWorkspacePinInstalls.set(pendingKey, verify);
  await verify;
}

async function verifyShareWorkspaceKeyDirectoryLineage(
  params: {
    workspaceId: string;
    workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
    workspaceKeyDirectoryLatestCheckpoint?: KeyDirectoryEnvelope | null;
    workspaceKeyDirectoryCheckpointAncestry?: KeyDirectoryEnvelope[];
    workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
    mismatchCode: string;
  },
  startedAt: number,
): Promise<void> {
  try {
    await advanceShareWorkspaceKeyDirectoryLineage(params);
    recordSharePinPerf("share_workspace_lineage_ready", {
      workspaceId: params.workspaceId,
      elapsedMs: performance.now() - startedAt,
    });
  } catch (error) {
    recordSharePinPerf("share_workspace_lineage_failed", {
      workspaceId: params.workspaceId,
      elapsedMs: performance.now() - startedAt,
      error: error instanceof Error ? error.message : String(error),
    });
    throw new Error(params.mismatchCode);
  }
}

async function advanceShareWorkspaceKeyDirectoryLineage(params: {
  workspaceId: string;
  workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
  workspaceKeyDirectoryLatestCheckpoint?: KeyDirectoryEnvelope | null;
  workspaceKeyDirectoryCheckpointAncestry?: KeyDirectoryEnvelope[];
  workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
}): Promise<void> {
  if (!params.workspaceKeyDirectoryLatestCheckpoint) return;

  const current = await getKeyDirectoryPin("workspace", params.workspaceId);
  if (!current) return;

  const latestSequence = checkpointSequence(params.workspaceKeyDirectoryLatestCheckpoint);
  const latestHash = hashKeyDirectoryCheckpointEnvelope(
    params.workspaceKeyDirectoryLatestCheckpoint,
  );
  if (latestSequence < current.checkpointSequence) {
    return;
  }
  if (latestSequence === current.checkpointSequence && latestHash !== current.checkpointHash) {
    throw new Error("share_workspace_key_directory_checkpoint_fork");
  }
  const checkpointAncestry = params.workspaceKeyDirectoryCheckpointAncestry ?? [];
  const eventAncestry = params.workspaceKeyDirectoryEventAncestry ?? [];
  if (latestSequence === current.checkpointSequence && latestHash === current.checkpointHash) {
    if (
      !params.workspaceKeyDirectoryCheckpoint ||
      (checkpointAncestry.length < 1 && eventAncestry.length < 1)
    ) {
      return;
    }
    await verifyAndRememberKeyDirectoryLineageFromTrustedAnchor({
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      trustedCheckpointEnvelope: params.workspaceKeyDirectoryCheckpoint,
      checkpointEnvelope: params.workspaceKeyDirectoryLatestCheckpoint,
      checkpointAncestry,
      eventAncestry,
      authorityEventAncestry: eventAncestry,
    });
    return;
  }

  const lineage = lineageFromCurrentPin(checkpointAncestry, eventAncestry, current);
  if (latestSequence > current.checkpointSequence) {
    if (!lineage) throw new Error("share_workspace_key_directory_lineage_missing");
  }

  try {
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      checkpointEnvelope: params.workspaceKeyDirectoryLatestCheckpoint,
      checkpointAncestry: lineage?.checkpointAncestry ?? checkpointAncestry,
      eventAncestry: lineage?.eventAncestry ?? eventAncestry,
      authorityEventAncestry: eventAncestry,
    });
  } catch (error) {
    if (latestSequence < current.checkpointSequence && isStaleLineageError(error)) return;
    throw error;
  }
}

function lineageFromCurrentPin(
  checkpointAncestry: KeyDirectoryEnvelope[],
  eventAncestry: KeyDirectoryEnvelope[],
  current: {
    checkpointSequence: number;
    checkpointHash: string;
    eventHeadSequence: number;
  },
): { checkpointAncestry: KeyDirectoryEnvelope[]; eventAncestry: KeyDirectoryEnvelope[] } | null {
  const currentCheckpointIndex = checkpointAncestry.findIndex(
    (checkpoint) =>
      checkpointSequence(checkpoint) === current.checkpointSequence &&
      hashKeyDirectoryCheckpointEnvelope(checkpoint) === current.checkpointHash,
  );
  if (currentCheckpointIndex < 0) return null;
  return {
    checkpointAncestry: checkpointAncestry.slice(currentCheckpointIndex),
    eventAncestry: eventAncestry.filter(
      (event) => keyDirectoryEventSequence(event) > current.eventHeadSequence,
    ),
  };
}

function isStaleLineageError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message === "key_directory_checkpoint_rollback" ||
      error.message === "key_directory_checkpoint_anchor_mismatch" ||
      error.message === "key_directory_checkpoint_fork" ||
      error.message === "key_directory_pin_conflict")
  );
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

function checkpointSequence(checkpointEnvelope: KeyDirectoryEnvelope): number {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const sequence = payload?.sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("workspace_key_directory_checkpoint_sequence_invalid");
  }
  return sequence;
}

function keyDirectoryEventSequence(event: KeyDirectoryEnvelope): number {
  const payload = event.payload as Record<string, unknown> | undefined;
  const sequence = payload?.sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("workspace_key_directory_event_sequence_invalid");
  }
  return sequence;
}
