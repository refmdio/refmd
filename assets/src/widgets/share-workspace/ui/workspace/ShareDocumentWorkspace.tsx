import { createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import { setOnEditorRegistered } from "@/features/editor";
import {
  bootstrapShareParticipantSession,
  enterShareRouteSession,
  leaveShareRouteSession,
  resolveShareDocumentRoute,
  type ResolvedShareFolderEntry,
} from "@/features/share";
import { getDocumentEvents } from "@/shared/lib/document/manager";
import { Spinner } from "@/shared/ui/spinner";
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

export function ShareDocumentWorkspace(props: { children: JSX.Element }) {
  const navigate = useNavigate();
  const params = useParams<{ documentToken?: string }>();
  const [error, setError] = createSignal<string | null>(null);
  const [shareRoot, setShareRoot] = createSignal<{
    shareSlug: string;
    documentToken: string;
    entry: ResolvedShareFolderEntry;
  } | null>(null);
  let requestVersion = 0;
  let pendingDocumentToken: string | null = null;
  let resolvedDocumentToken: string | null = null;
  let reentryHash = window.location.hash;

  enterShareRouteSession();
  onCleanup(() => leaveShareRouteSession());
  onCleanup(() => setOnEditorRegistered(() => {}));

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
    if (shareRoot()?.documentToken !== documentToken) setShareRoot(null);

    void (async () => {
      try {
        const resolved = await resolveShareDocumentRoute(documentToken);
        if (currentRequest !== requestVersion) return;

        let ready = resolved;
        if (ready.kind === "bootstrap-required") {
          const shareSlug = ready.shareSlug;
          try {
            await bootstrapShareParticipantSession(shareSlug);
            ready = await resolveShareDocumentRoute(documentToken);
          } catch {
            if (currentRequest === requestVersion) pendingDocumentToken = null;
            navigate(shareLandingPath(shareSlug, reentryHash), {
              replace: true,
              scroll: false,
            });
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
        setShareRoot({
          shareSlug: ready.access.shareSlug,
          documentToken,
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
      } catch {
        if (currentRequest !== requestVersion) return;
        pendingDocumentToken = null;
        resolvedDocumentToken = null;
        setError("Share document not found.");
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
          reentryHash={reentryHash}
          selectedToken={shareRoot()!.documentToken}
        >
          {props.children}
        </ShareWorkspaceShell>
      ) : (
        <div class="flex h-screen w-screen items-center justify-center bg-background p-6">
          <Spinner class="size-6" />
        </div>
      )}
    </>
  );
}
