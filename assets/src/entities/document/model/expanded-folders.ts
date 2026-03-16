import { createSignal, createEffect, type Accessor } from "solid-js";

function storageKey(workspaceId: string): string {
  return `refmd_expanded_folders:${workspaceId}`;
}

function loadExpanded(workspaceId: string): Set<string> {
  try {
    const raw = localStorage.getItem(storageKey(workspaceId));
    if (!raw) return new Set<string>();
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) return new Set<string>(arr);
    return new Set<string>();
  } catch {
    return new Set<string>();
  }
}

function saveExpanded(workspaceId: string, set: Set<string>): void {
  try {
    localStorage.setItem(storageKey(workspaceId), JSON.stringify([...set]));
  } catch {
    // Ignore storage errors
  }
}

export function useExpandedFolders(workspaceId: Accessor<string | null>) {
  const [expanded, setExpanded] = createSignal<Set<string>>(new Set());

  createEffect(() => {
    const wsId = workspaceId();
    if (wsId) {
      setExpanded(loadExpanded(wsId));
    } else {
      setExpanded(new Set<string>());
    }
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
    saveExpanded(wsId, next);
  }

  function expand(folderId: string): void {
    const wsId = workspaceId();
    if (!wsId) return;
    const next = new Set(expanded());
    next.add(folderId);
    setExpanded(next);
    saveExpanded(wsId, next);
  }

  return { isExpanded, toggle, expand };
}
