import { useNavigate } from "@solidjs/router";
import {
  ChevronDownIcon,
  ChevronRightIcon,
  FileTextIcon,
  FolderIcon,
  LinkIcon,
  PanelRightIcon,
  PlusIcon,
} from "lucide-solid";
import { createEffect, createMemo, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import type { ShareLinkMount } from "@/entities/mount";
import { authState } from "@/entities/session";
import {
  activateSharedDocumentRoute,
  clearShareReentry,
  disposeSharedDocumentRoute,
  getDocumentState,
  needsShareReentry,
  primeDocumentContentPreview,
  prewarmShareDocumentSigningKeyCaches,
  setFocusedPanelIdAccessor,
} from "@/features/editor";
import {
  createShareLinkWorkspaceTileTarget,
  disposePanelWorkspace,
  usePanelWorkspace,
} from "@/features/panel";
import {
  bootstrapShareParticipantSession,
  resolveShareFolderRoute,
  resolveShareDocumentRoute,
  SaveShareMountButton,
  useSaveShareMount,
  type ResolvedShareDocumentRoute,
  type ResolvedShareFolderEntry,
} from "@/features/share";
import { getDocumentEvents } from "@/shared/lib/document/manager";
import { Notice } from "@/shared/lib/notice";
import { sharesApi } from "@/shared/api";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/shared/ui/context-menu";
import { Spinner } from "@/shared/ui/spinner";

export interface ShareTreeNode {
  entry: ResolvedShareFolderEntry;
  children: ShareTreeNode[];
  depth: number;
}

type ReadyShareDocumentRoute = Extract<ResolvedShareDocumentRoute, { kind: "ready" }>;

function recordShareWorkspacePerf(event: string, detail: Record<string, unknown>): void {
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

interface ShareWorkspaceShellProps {
  shareSlug: string;
  title: string;
  root: ResolvedShareFolderEntry;
  entries: ResolvedShareFolderEntry[];
  initialDocumentToken?: string | null;
  initialResolvedDocument?: ReadyShareDocumentRoute | null;
  reentryHash?: string | null;
  selectedToken?: string | null;
  existingMounts?: ShareLinkMount[];
  children: JSX.Element;
}

function buildShareTree(
  root: ResolvedShareFolderEntry,
  entries: ResolvedShareFolderEntry[],
): ShareTreeNode[] {
  const childrenByParent = new Map<string | null, ResolvedShareFolderEntry[]>();
  for (const entry of entries) {
    const siblings = childrenByParent.get(entry.parent_id ?? null) ?? [];
    siblings.push(entry);
    childrenByParent.set(entry.parent_id ?? null, siblings);
  }

  const visit = (entry: ResolvedShareFolderEntry, depth: number): ShareTreeNode => ({
    entry,
    depth,
    children: (childrenByParent.get(entry.id) ?? []).map((child) => visit(child, depth + 1)),
  });

  return [visit(root, 0)];
}

function entryToken(entry: ResolvedShareFolderEntry): string | null {
  return entry.doc_type === "folder" ? entry.folder_token : entry.document_token;
}

function shareLandingPath(shareSlug: string, fallbackHash?: string | null): string {
  return `/share/${shareSlug}${window.location.hash || fallbackHash || ""}`;
}

export function ShareWorkspaceShell(props: ShareWorkspaceShellProps) {
  const navigate = useNavigate();
  const workspace = usePanelWorkspace();
  const [expanded, setExpanded] = createSignal(new Set<string>([props.root.id]));
  const [openingToken, setOpeningToken] = createSignal<string | null>(null);
  const [loadingFolderId, setLoadingFolderId] = createSignal<string | null>(null);
  const [loadedFolderIds, setLoadedFolderIds] = createSignal(new Set<string>());
  const [treeEntries, setTreeEntries] = createSignal<ResolvedShareFolderEntry[]>(props.entries);
  const [registeredTargetKeys, setRegisteredTargetKeys] = createSignal<Set<string>>(new Set());
  const [shareLinkMounts, setShareLinkMounts] = createSignal<ShareLinkMount[]>([]);
  const tree = createMemo(() => buildShareTree(props.root, treeEntries()));
  const selectedToken = () => props.selectedToken ?? null;
  const userSessionAvailable = () => !!authState();
  const existingMounts = () => props.existingMounts ?? shareLinkMounts();
  let openedInitialToken: string | null = null;

  const toggle = (id: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const mergeTreeEntries = (entries: ResolvedShareFolderEntry[]) => {
    setTreeEntries((current) => {
      const byId = new Map(current.map((entry) => [entry.id, entry]));
      for (const entry of entries) byId.set(entry.id, entry);
      return [...byId.values()].sort((a, b) => {
        const parentDiff = (a.parent_id ?? "").localeCompare(b.parent_id ?? "");
        if (parentDiff !== 0) return parentDiff;
        const positionDiff = (a.position ?? 0) - (b.position ?? 0);
        if (positionDiff !== 0) return positionDiff;
        return a.id.localeCompare(b.id);
      });
    });
  };

  const expandFolderEntry = async (entry: ResolvedShareFolderEntry) => {
    toggle(entry.id);
    if (!entry.folder_token || loadedFolderIds().has(entry.id)) return;

    setLoadingFolderId(entry.id);
    try {
      const resolved = await resolveShareFolderRoute(entry.folder_token);
      if (resolved.kind === "bootstrap-required") {
        navigate(shareLandingPath(resolved.shareSlug, props.reentryHash), {
          replace: true,
          scroll: false,
        });
        return;
      }

      mergeTreeEntries(resolved.entries);
      setLoadedFolderIds((current) => new Set(current).add(entry.id));
    } catch {
      new Notice("Failed to load shared folder");
    } finally {
      setLoadingFolderId(null);
    }
  };

  const rememberTargetKey = (targetKey: string) => {
    setRegisteredTargetKeys((current) => new Set(current).add(targetKey));
  };

  const refreshShareLinkMounts = async () => {
    if (props.existingMounts || !userSessionAvailable()) return;

    try {
      const response = await sharesApi.listShareLinkMounts(props.shareSlug);
      setShareLinkMounts(response.mounts);
    } catch {
      setShareLinkMounts([]);
    }
  };

  const initialResolvedDocument = (documentToken: string): ReadyShareDocumentRoute | null => {
    const resolved = props.initialResolvedDocument;
    return resolved?.target.documentToken === documentToken ? resolved : null;
  };

  const openDocumentToken = async (documentToken: string) => {
    const startedAt = performance.now();
    recordShareWorkspacePerf("share_workspace_open_document_started", { documentToken });
    setOpeningToken(documentToken);
    try {
      let resolved =
        initialResolvedDocument(documentToken) ?? (await resolveShareDocumentRoute(documentToken));
      if (resolved.kind === "bootstrap-required") {
        const shareSlug = resolved.shareSlug;
        try {
          await bootstrapShareParticipantSession(shareSlug);
          resolved = await resolveShareDocumentRoute(documentToken);
        } catch {
          navigate(shareLandingPath(shareSlug, props.reentryHash), {
            replace: true,
            scroll: false,
          });
          return;
        }
        if (resolved.kind === "bootstrap-required") {
          navigate(shareLandingPath(resolved.shareSlug, props.reentryHash), {
            replace: true,
            scroll: false,
          });
          return;
        }
      }

      recordShareWorkspacePerf("share_workspace_open_document_route_ready", {
        documentToken,
        documentId: resolved.target.documentId,
        elapsedMs: performance.now() - startedAt,
      });
      const target = createShareLinkWorkspaceTileTarget(resolved.target);
      activateSharedDocumentRoute(target.targetKey, resolved.access);
      prewarmShareDocumentSigningKeyCaches({
        kind: "share",
        source: "link",
        ...resolved.access,
      });
      void primeDocumentContentPreview(
        resolved.target.documentId,
        resolved.target.workspaceId,
        target.targetKey,
      );
      recordShareWorkspacePerf("share_workspace_open_document_access_ready", {
        documentToken,
        documentId: resolved.target.documentId,
        targetKey: target.targetKey,
        elapsedMs: performance.now() - startedAt,
      });
      workspace.openDocument(target);
      rememberTargetKey(target.targetKey);
      getDocumentEvents().flushPendingOpens();
      recordShareWorkspacePerf("share_workspace_open_document_ready", {
        documentToken,
        documentId: resolved.target.documentId,
        targetKey: target.targetKey,
        elapsedMs: performance.now() - startedAt,
      });
    } finally {
      setOpeningToken(null);
    }
  };

  const openEntry = (entry: ResolvedShareFolderEntry) => {
    if (entry.doc_type === "folder") {
      void expandFolderEntry(entry);
      return;
    }

    if (entry.document_token) void openDocumentToken(entry.document_token);
  };

  const disposeRegisteredTargets = () => {
    for (const targetKey of registeredTargetKeys()) {
      disposeSharedDocumentRoute(targetKey);
    }
    setRegisteredTargetKeys(new Set<string>());
  };

  const dispose = () => {
    disposeRegisteredTargets();
    disposePanelWorkspace();
  };

  createEffect(() => {
    setFocusedPanelIdAccessor(() => workspace.focusedPanelId());
  });

  onCleanup(() => setFocusedPanelIdAccessor(() => null));

  createEffect(() => {
    if (props.existingMounts) {
      setShareLinkMounts([]);
      return;
    }

    if (!userSessionAvailable()) {
      setShareLinkMounts([]);
      return;
    }

    let cancelled = false;
    void sharesApi
      .listShareLinkMounts(props.shareSlug)
      .then((response) => {
        if (!cancelled) setShareLinkMounts(response.mounts);
      })
      .catch(() => {
        if (!cancelled) setShareLinkMounts([]);
      });

    onCleanup(() => {
      cancelled = true;
    });
  });

  createEffect(() => {
    setExpanded(new Set([props.root.id]));
    setLoadedFolderIds(new Set([props.root.id]));
    setTreeEntries(props.entries);
  });

  createEffect(() => {
    const token = props.initialDocumentToken;
    if (!token || openedInitialToken === token) return;
    openedInitialToken = token;
    recordShareWorkspacePerf("share_workspace_initial_document_requested", {
      documentToken: token,
    });
    void openDocumentToken(token);
  });

  createEffect(() => {
    for (const stateKey of registeredTargetKeys()) {
      if (!needsShareReentry(stateKey)) continue;

      const state = getDocumentState(stateKey);
      if (state?.access.kind !== "share") continue;

      clearShareReentry(stateKey);
      navigate(shareLandingPath(state.access.shareSlug, props.reentryHash), {
        replace: true,
        scroll: false,
      });
      return;
    }
  });

  return (
    <main class="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      <aside class="flex h-full w-72 shrink-0 flex-col border-r border-border bg-sidebar text-sidebar-foreground">
        <div class="flex-1 overflow-y-auto py-2">
          <For each={tree()}>
            {(node) => (
              <ShareTreeItem
                node={node}
                expanded={expanded()}
                selectedToken={selectedToken()}
                openingToken={openingToken()}
                loadingFolderId={loadingFolderId()}
                existingMounts={existingMounts()}
                sessionAvailable={userSessionAvailable()}
                shareSlug={props.shareSlug}
                rootTitle={props.title}
                onMountSaved={() => {
                  void refreshShareLinkMounts();
                }}
                onToggle={toggle}
                onOpen={openEntry}
              />
            )}
          </For>
        </div>

        <div class="border-t border-sidebar-border px-2 py-1">
          <div class="flex h-9 items-center gap-2 px-3 text-xs text-sidebar-foreground/75">
            <LinkIcon class="size-4 shrink-0 opacity-50" />
            <span class="truncate font-bold">Shared</span>
          </div>
        </div>
      </aside>

      <section class="min-w-0 flex-1">{props.children}</section>
      <ShareWorkspaceDisposer dispose={dispose} />
    </main>
  );
}

function ShareWorkspaceDisposer(props: { dispose: () => void }) {
  if (typeof window !== "undefined") {
    window.addEventListener("pagehide", props.dispose, { once: true });
    onCleanup(() => {
      window.removeEventListener("pagehide", props.dispose);
    });
  }
  onCleanup(props.dispose);
  return null;
}

function ShareTreeItem(props: {
  node: ShareTreeNode;
  expanded: Set<string>;
  selectedToken: string | null;
  openingToken: string | null;
  loadingFolderId: string | null;
  existingMounts?: ShareLinkMount[];
  sessionAvailable: boolean;
  shareSlug: string;
  rootTitle: string;
  onMountSaved: () => void;
  onToggle: (id: string) => void;
  onOpen: (entry: ResolvedShareFolderEntry) => void;
}) {
  const entry = () => props.node.entry;
  const mountTargetTitle = () => (props.node.depth === 0 ? props.rootTitle : entry().label);
  const isFolder = () => entry().doc_type === "folder";
  const token = () => entryToken(entry());
  const selected = () => token() != null && token() === props.selectedToken;
  const hasChildren = () => props.node.children.length > 0;
  const saveMount = useSaveShareMount({
    shareSlug: props.shareSlug,
    targetKind: isFolder() ? "folder" : "document",
    targetToken: token(),
    targetDocumentId: entry().id,
    targetTitle: mountTargetTitle(),
    existingMounts: props.existingMounts,
    sessionAvailable: props.sessionAvailable,
    onSaved: props.onMountSaved,
  });

  return (
    <div>
      <div class="relative">
        <ContextMenu modal={false}>
          <ContextMenuTrigger class="contents">
            <button
              type="button"
              class="flex w-full min-w-0 items-center gap-1.5 py-1.5 pr-10 text-left text-xs transition-colors hover:bg-sidebar-accent"
              classList={{
                "bg-sidebar-accent text-sidebar-foreground": selected(),
              }}
              style={{ "padding-left": `${props.node.depth * 16 + 8}px` }}
              onClick={() => props.onOpen(entry())}
            >
              <Show when={isFolder()} fallback={<span class="size-4 shrink-0" />}>
                <span
                  class="flex size-4 shrink-0 items-center justify-center"
                  onClick={(event) => {
                    event.stopPropagation();
                    props.onOpen(entry());
                  }}
                >
                  <Show
                    when={props.expanded.has(entry().id)}
                    fallback={<ChevronRightIcon class="size-3" />}
                  >
                    <ChevronDownIcon class="size-3" />
                  </Show>
                </span>
              </Show>
              <Show
                when={isFolder()}
                fallback={<FileTextIcon class="size-4 shrink-0 text-muted-foreground" />}
              >
                <FolderIcon class="size-4 shrink-0 text-muted-foreground" />
              </Show>
              <span class="truncate">{entry().label}</span>
              <Show when={props.openingToken === token()}>
                <Spinner class="ml-auto size-3 shrink-0" />
              </Show>
              <Show when={props.loadingFolderId === entry().id}>
                <Spinner class="ml-auto size-3 shrink-0" />
              </Show>
            </button>
          </ContextMenuTrigger>
          <ContextMenuContent>
            <ContextMenuItem onSelect={() => props.onOpen(entry())}>
              <PanelRightIcon class="size-3.5" />
              {isFolder() ? "Open folder" : "Open"}
            </ContextMenuItem>
            <Show when={props.sessionAvailable}>
              <ContextMenuSeparator />
              <ContextMenuItem
                disabled={!saveMount.canSave() || saveMount.saving()}
                onSelect={() => {
                  void saveMount.save();
                }}
              >
                <PlusIcon class="size-3.5" />
                {saveMount.isSaved() ? "Already saved" : "Add to workspace"}
              </ContextMenuItem>
            </Show>
          </ContextMenuContent>
        </ContextMenu>
        <div
          class="absolute right-2 top-1/2 z-10 -translate-y-1/2"
          onClick={(event) => event.stopPropagation()}
          onMouseDown={(event) => event.stopPropagation()}
        >
          <SaveShareMountButton
            shareSlug={props.shareSlug}
            targetKind={isFolder() ? "folder" : "document"}
            targetToken={token()}
            targetDocumentId={entry().id}
            targetTitle={mountTargetTitle()}
            existingMounts={props.existingMounts}
            sessionAvailable={props.sessionAvailable}
            onSaved={props.onMountSaved}
            iconOnly
            class="size-6 bg-transparent text-sidebar-foreground/70 shadow-none hover:bg-sidebar-accent/70 hover:text-sidebar-foreground disabled:bg-transparent disabled:opacity-100"
          />
        </div>
      </div>
      <Show when={isFolder() && hasChildren() && props.expanded.has(entry().id)}>
        <For each={props.node.children}>
          {(child) => (
            <ShareTreeItem
              node={child}
              expanded={props.expanded}
              selectedToken={props.selectedToken}
              openingToken={props.openingToken}
              loadingFolderId={props.loadingFolderId}
              existingMounts={props.existingMounts}
              sessionAvailable={props.sessionAvailable}
              shareSlug={props.shareSlug}
              rootTitle={props.rootTitle}
              onMountSaved={props.onMountSaved}
              onToggle={props.onToggle}
              onOpen={props.onOpen}
            />
          )}
        </For>
      </Show>
    </div>
  );
}
