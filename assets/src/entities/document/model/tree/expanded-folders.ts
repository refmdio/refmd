import { createSignal, createEffect, onCleanup, type Accessor } from "solid-js";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

function storageKey(workspaceId: string): string {
  return `refmd-expanded-folders:${workspaceId}`;
}

function aadRecord(workspaceId: string): Record<string, unknown> {
  return {
    kind: "expanded_folders",
    workspace_id: workspaceId,
  };
}

async function loadExpanded(workspaceId: string): Promise<Set<string>> {
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return new Set<string>();
    const expectedAad = aadRecord(workspaceId);
    const plaintext = await worker.loadUiStateWithDsk({
      storageKey: storageKey(workspaceId),
      aadRecord: expectedAad,
    });
    if (!plaintext) return new Set<string>();
    const arr = JSON.parse(new TextDecoder().decode(plaintext));
    if (Array.isArray(arr)) return new Set<string>(arr);
    return new Set<string>();
  } catch {
    return new Set<string>();
  }
}

async function saveExpanded(workspaceId: string, set: Set<string>): Promise<void> {
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return;
    const aad = aadRecord(workspaceId);
    await worker.storeUiStateWithDsk({
      storageKey: storageKey(workspaceId),
      plaintext: new TextEncoder().encode(JSON.stringify([...set])),
      aadRecord: aad,
    });
  } catch {
    // Ignore cache errors; expanded state remains in memory for this tab.
  }
}

export function useExpandedFolders(workspaceId: Accessor<string | null>) {
  const [expanded, setExpanded] = createSignal<Set<string>>(new Set());

  createEffect(() => {
    const wsId = workspaceId();
    let cancelled = false;
    if (wsId) {
      void loadExpanded(wsId).then((loaded) => {
        if (!cancelled) setExpanded(loaded);
      });
    } else {
      setExpanded(new Set<string>());
    }
    onCleanup(() => {
      cancelled = true;
    });
  });

  function isExpanded(folderId: string): boolean {
    return expanded().has(folderId);
  }

  function toggle(folderId: string): void {
    const wsId = workspaceId();
    if (!wsId) return;
    const next = new Set(expanded());
    if (next.has(folderId)) {
      next.delete(folderId);
    } else {
      next.add(folderId);
    }
    setExpanded(next);
    void saveExpanded(wsId, next);
  }

  function expand(folderId: string): void {
    const wsId = workspaceId();
    if (!wsId) return;
    const next = new Set(expanded());
    next.add(folderId);
    setExpanded(next);
    void saveExpanded(wsId, next);
  }

  return { isExpanded, toggle, expand };
}
