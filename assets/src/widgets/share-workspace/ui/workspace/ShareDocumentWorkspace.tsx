import { createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import { readShareSlugFromLocation } from "@/entities/mount";
import {
  activateSharedDocumentRoute,
  disposeSharedDocumentRoute,
  primeDocumentContentPreview,
  prewarmShareDocumentSigningKeyCaches,
  setOnEditorRegistered,
} from "@/features/editor";
import { createShareLinkWorkspaceTileTarget } from "@/features/panel";
import {
  bootstrapShareParticipantSession,
  consumePreloadedShareDocumentRoute,
  enterShareRouteSession,
  leaveShareRouteSession,
  resolveShareDocumentRoute,
  type ResolvedShareDocumentRoute,
  type ResolvedShareFolderEntry,
  ShareRoutePhaseContent,
  type ShareRoutePhase,
} from "@/features/share";
import { ApiError } from "@/shared/api";
import { getDocumentEvents } from "@/shared/lib/document/manager";
import { ShareWorkspaceShell } from "./ShareWorkspaceShell";

function shareLandingPath(shareSlug: string, fallbackHash?: string | null): string {
  return `/share/${shareSlug}${window.location.hash || fallbackHash || ""}`;
}

function clearCanonicalHash(): void {
  if (!window.location.hash) return;
}

function ensureCanonicalShareHash(shareSlug: string): string {
  const params = new URLSearchParams();
  params.set("s", shareSlug);
  const hash = `#${params.toString()}`;
  if (window.location.hash === hash) return hash;
  window.history.replaceState(
    window.history.state,
    "",
    `${window.location.pathname}${window.location.search}${hash}`,
  );
  return hash;
}

type ReadyShareDocumentRoute = Extract<ResolvedShareDocumentRoute, { kind: "ready" }>;
const SHARE_DOCUMENT_PROGRESS = {
  resolving: {
    label: "Resolving shared document",
    detail: "Checking the document route and share session state.",
    value: 18,
  },
  restoringSession: {
    label: "Restoring anonymous session",
    detail: "Recreating share access material before opening the document.",
    value: 42,
  },
  resolvingAfterSession: {
    label: "Verifying restored access",
    detail: "Rechecking the document route with the restored anonymous session.",
    value: 52,
  },
  keys: {
    label: "Preparing document keys",
    detail: "Warming signing and key-directory verification caches.",
    value: 60,
  },
  mountingWorkspace: {
    label: "Mounting share workspace",
    detail: "Connecting the document route to the workspace surface.",
    value: 74,
  },
  primingContent: {
    label: "Preparing document content",
    detail: "Priming the first encrypted content preview before editor mount.",
    value: 86,
  },
  mountingDom: {
    label: "Mounting editor DOM",
    detail: "Rendering the shared document workspace and editor surfaces.",
    value: 96,
  },
} satisfies Record<string, ShareRoutePhase>;

function shareRouteErrorCode(error: unknown): string | null {
  if (error instanceof ApiError) return error.code;
  return error instanceof Error && error.message ? error.message : null;
}

function isShareDocumentNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

function isShareBootstrapMaterialError(error: unknown): boolean {
  const code = shareRouteErrorCode(error);
  return (
    code === "share_session_required" ||
    code === "share_capability_secret_required" ||
    code === "workspace_pin_bootstrap_hash_required"
  );
}

function shareDocumentRouteErrorMessage(error: unknown): string {
  if (isShareDocumentNotFound(error)) return "Share document not found.";
  if (isShareBootstrapMaterialError(error)) return "Invalid share link.";
  return "Unable to verify shared document.";
}

function recordShareDocumentWorkspacePerf(event: string, detail: Record<string, unknown>): void {
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

function preloadDocumentEditorModule(): void {
  void import("@/widgets/document-editor").catch(() => {});
}

async function resolveDocumentRoute(documentToken: string): Promise<ResolvedShareDocumentRoute> {
  const preloaded = consumePreloadedShareDocumentRoute(documentToken);
  if (!preloaded) return resolveShareDocumentRoute(documentToken);

  try {
    return await preloaded;
  } catch {
    return resolveShareDocumentRoute(documentToken);
  }
}

export function ShareDocumentWorkspace(props: { children: JSX.Element }) {
  const navigate = useNavigate();
  const params = useParams<{ documentToken?: string }>();
  const [error, setError] = createSignal<string | null>(null);
  const [shareRoot, setShareRoot] = createSignal<{
    shareSlug: string;
    documentToken: string;
    entry: ResolvedShareFolderEntry;
    resolved: ReadyShareDocumentRoute;
  } | null>(null);
  const [progress, setProgress] = createSignal<ShareRoutePhase>(SHARE_DOCUMENT_PROGRESS.resolving);
  let requestVersion = 0;
  let pendingDocumentToken: string | null = null;
  let resolvedDocumentToken: string | null = null;
  let preactivatedStateKey: string | null = null;
  let reentryHash = window.location.hash;

  enterShareRouteSession();
  onCleanup(() => leaveShareRouteSession());
  onCleanup(() => setOnEditorRegistered(() => {}));
  onCleanup(() => {
    if (preactivatedStateKey) disposeSharedDocumentRoute(preactivatedStateKey);
  });

  setOnEditorRegistered(() => {
    getDocumentEvents().flushPendingOpens();
    clearCanonicalHash();
  });

  createEffect(() => {
    const documentToken = params.documentToken;
    if (!documentToken) {
      requestVersion += 1;
      pendingDocumentToken = null;
      resolvedDocumentToken = null;
      setError("Invalid share document route.");
      setShareRoot(null);
      return;
    }

    if (
      (resolvedDocumentToken === documentToken && shareRoot()?.documentToken === documentToken) ||
      pendingDocumentToken === documentToken
    ) {
      return;
    }

    const currentRequest = ++requestVersion;
    pendingDocumentToken = documentToken;
    setError(null);
    setProgress(SHARE_DOCUMENT_PROGRESS.resolving);
    recordShareDocumentWorkspacePerf("share_document_workspace_route_started", {
      documentToken,
    });
    preloadDocumentEditorModule();
    if (shareRoot()?.documentToken !== documentToken) setShareRoot(null);

    void (async () => {
      try {
        const resolved = await resolveDocumentRoute(documentToken);
        if (currentRequest !== requestVersion) return;
        recordShareDocumentWorkspacePerf("share_document_workspace_route_resolved", {
          documentToken,
          kind: resolved.kind,
        });

        let ready = resolved;
        if (ready.kind === "bootstrap-required") {
          const shareSlug = ready.shareSlug;
          try {
            setProgress(SHARE_DOCUMENT_PROGRESS.restoringSession);
            await bootstrapShareParticipantSession(shareSlug);
            setProgress(SHARE_DOCUMENT_PROGRESS.resolvingAfterSession);
            ready = await resolveShareDocumentRoute(documentToken);
          } catch (error) {
            if (currentRequest === requestVersion) pendingDocumentToken = null;
            if (isShareBootstrapMaterialError(error)) {
              navigate(shareLandingPath(shareSlug, reentryHash), {
                replace: true,
                scroll: false,
              });
            } else {
              setError(shareDocumentRouteErrorMessage(error));
            }
            return;
          }
          if (currentRequest !== requestVersion) return;
          if (ready.kind === "bootstrap-required") {
            pendingDocumentToken = null;
            navigate(shareLandingPath(ready.shareSlug, reentryHash), {
              replace: true,
              scroll: false,
            });
            return;
          }
        }

        pendingDocumentToken = null;
        resolvedDocumentToken = documentToken;
        reentryHash = ensureCanonicalShareHash(ready.access.shareSlug) || reentryHash;
        setProgress(SHARE_DOCUMENT_PROGRESS.keys);
        prewarmShareDocumentSigningKeyCaches({
          kind: "share",
          source: "link",
          ...ready.access,
        });
        const target = createShareLinkWorkspaceTileTarget(ready.target);
        if (preactivatedStateKey && preactivatedStateKey !== target.targetKey) {
          disposeSharedDocumentRoute(preactivatedStateKey);
        }
        preactivatedStateKey = target.targetKey;
        setProgress(SHARE_DOCUMENT_PROGRESS.mountingWorkspace);
        activateSharedDocumentRoute(target.targetKey, ready.access);
        setProgress(SHARE_DOCUMENT_PROGRESS.primingContent);
        await primeDocumentContentPreview(
          ready.target.documentId,
          ready.target.workspaceId,
          target.targetKey,
        );
        if (currentRequest !== requestVersion) return;
        recordShareDocumentWorkspacePerf("share_document_workspace_content_ready", {
          documentToken,
          documentId: ready.target.documentId,
          stateKey: target.targetKey,
        });
        setProgress(SHARE_DOCUMENT_PROGRESS.mountingDom);
        setShareRoot({
          shareSlug: ready.access.shareSlug,
          documentToken,
          resolved: ready,
          entry: {
            id: ready.target.documentId,
            share_id: ready.access.shareId,
            doc_type: "document",
            document_token: documentToken,
            folder_token: null,
            encrypted_key_refs: ready.access.encryptedKeyRefs,
            encrypted_title: null,
            encrypted_title_key_version: null,
            encrypted_title_nonce: null,
            key_version: ready.access.keyVersion,
            workspace_pin_bootstrap: (ready.access.workspacePinBootstrap ?? null) as never,
            parent_id: null,
            position: null,
            label: ready.target.title ?? "Shared document",
          },
        });
        recordShareDocumentWorkspacePerf("share_document_workspace_root_ready", {
          documentToken,
          documentId: ready.target.documentId,
          stateKey: target.targetKey,
        });
      } catch (error) {
        if (currentRequest !== requestVersion) return;
        pendingDocumentToken = null;
        resolvedDocumentToken = null;
        const shareSlug = readShareSlugFromLocation();
        if (shareSlug && isShareBootstrapMaterialError(error)) {
          navigate(shareLandingPath(shareSlug, reentryHash), {
            replace: true,
            scroll: false,
          });
          return;
        }
        setError(shareDocumentRouteErrorMessage(error));
      }
    })();
  });

  return (
    <>
      {error() ? (
        <div class="flex h-screen w-screen items-center justify-center bg-background p-6 text-sm text-muted-foreground">
          {error()}
        </div>
      ) : shareRoot() ? (
        <ShareWorkspaceShell
          shareSlug={shareRoot()!.shareSlug}
          title={shareRoot()!.entry.label}
          root={shareRoot()!.entry}
          entries={[]}
          initialDocumentToken={shareRoot()!.documentToken}
          initialResolvedDocument={shareRoot()!.resolved}
          reentryHash={reentryHash}
          selectedToken={shareRoot()!.documentToken}
        >
          {props.children}
        </ShareWorkspaceShell>
      ) : (
        <div class="flex h-screen w-screen items-center justify-center bg-background p-6">
          <ShareRoutePhaseContent phase={progress()} />
        </div>
      )}
    </>
  );
}
