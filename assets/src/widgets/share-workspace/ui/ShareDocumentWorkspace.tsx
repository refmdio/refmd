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

  enterShareRouteSession();
  onCleanup(() => leaveShareRouteSession());
  onCleanup(() => setOnEditorRegistered(() => {}));

  setOnEditorRegistered(() => getDocumentEvents().flushPendingOpens());

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
            navigate(`/share/${shareSlug}`, {
              replace: true,
              scroll: false,
            });
            return;
          }
          if (currentRequest !== requestVersion) return;
          if (ready.kind === "bootstrap-required") {
            pendingDocumentToken = null;
            navigate(`/share/${ready.shareSlug}`, {
              replace: true,
              scroll: false,
            });
            return;
          }
        }

        pendingDocumentToken = null;
        resolvedDocumentToken = documentToken;
        setShareRoot({
          shareSlug: ready.access.shareSlug,
          documentToken,
          entry: {
            id: ready.target.documentId,
            share_id: ready.access.shareId,
            doc_type: "document",
            document_token: documentToken,
            folder_token: null,
            encrypted_dek: ready.access.encryptedDek,
            encrypted_title: null,
            encrypted_title_key_version: null,
            encrypted_title_nonce: null,
            key_version: ready.access.keyVersion,
            nonce: ready.access.nonce,
            parent_id: null,
            position: null,
            title: ready.target.title ?? null,
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
