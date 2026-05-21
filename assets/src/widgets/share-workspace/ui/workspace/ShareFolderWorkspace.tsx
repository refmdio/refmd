import { createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import {
  bootstrapShareParticipantSession,
  enterShareRouteSession,
  leaveShareRouteSession,
  resolveShareFolderRoute,
  type ResolvedShareFolderEntry,
} from "@/features/share";
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

export function ShareFolderWorkspace(props: { children: JSX.Element }) {
  const navigate = useNavigate();
  const params = useParams<{ folderToken?: string }>();
  const [error, setError] = createSignal<string | null>(null);
  const [folder, setFolder] = createSignal<ResolvedShareFolderEntry | null>(null);
  const [entries, setEntries] = createSignal<ResolvedShareFolderEntry[]>([]);
  const [shareSlug, setShareSlug] = createSignal<string | null>(null);
  const [loaded, setLoaded] = createSignal(false);
  let requestVersion = 0;
  let pendingFolderToken: string | null = null;
  let resolvedFolderToken: string | null = null;
  let reentryHash = window.location.hash;

  enterShareRouteSession();
  onCleanup(() => leaveShareRouteSession());

  createEffect(() => {
    const folderToken = params.folderToken;
    if (!folderToken) {
      requestVersion += 1;
      pendingFolderToken = null;
      resolvedFolderToken = null;
      setError("Invalid share folder route.");
      setFolder(null);
      setEntries([]);
      setShareSlug(null);
      setLoaded(true);
      return;
    }

    if (
      (resolvedFolderToken === folderToken && folder()?.folder_token === folderToken) ||
      pendingFolderToken === folderToken
    ) {
      return;
    }

    const currentRequest = ++requestVersion;
    pendingFolderToken = folderToken;
    setError(null);
    if (folder()?.folder_token !== folderToken) {
      setFolder(null);
      setEntries([]);
      setShareSlug(null);
      setLoaded(false);
    }

    void (async () => {
      try {
        const resolved = await resolveShareFolderRoute(folderToken);
        if (currentRequest !== requestVersion) return;

        let ready = resolved;
        if (ready.kind === "bootstrap-required") {
          const shareSlug = ready.shareSlug;
          try {
            await bootstrapShareParticipantSession(shareSlug);
            ready = await resolveShareFolderRoute(folderToken);
          } catch {
            if (currentRequest === requestVersion) pendingFolderToken = null;
            navigate(shareLandingPath(shareSlug, reentryHash), {
              replace: true,
              scroll: false,
            });
            return;
          }
          if (currentRequest !== requestVersion) return;
          if (ready.kind === "bootstrap-required") {
            pendingFolderToken = null;
            navigate(shareLandingPath(ready.shareSlug, reentryHash), {
              replace: true,
              scroll: false,
            });
            return;
          }
        }

        pendingFolderToken = null;
        resolvedFolderToken = folderToken;
        reentryHash = ensureCanonicalShareHash(ready.shareSlug) || reentryHash;
        clearCanonicalHash();
        setFolder(ready.folder);
        setEntries(ready.entries);
        setShareSlug(ready.shareSlug);
        setLoaded(true);
      } catch {
        if (currentRequest !== requestVersion) return;
        pendingFolderToken = null;
        resolvedFolderToken = null;
        setError("Share folder not found.");
        setLoaded(true);
      }
    })();
  });

  return (
    <>
      {error() ? (
        <div class="flex h-screen w-screen items-center justify-center bg-background text-sm text-muted-foreground">
          {error()}
        </div>
      ) : !loaded() ? (
        <div class="flex h-screen w-screen items-center justify-center bg-background">
          <Spinner class="size-6" />
        </div>
      ) : folder() && shareSlug() ? (
        <ShareWorkspaceShell
          shareSlug={shareSlug()!}
          title={folder()!.label}
          root={folder()!}
          entries={entries()}
          reentryHash={reentryHash}
          selectedToken={params.folderToken ?? null}
        >
          {props.children}
        </ShareWorkspaceShell>
      ) : (
        <div class="flex h-screen w-screen items-center justify-center bg-background text-sm text-muted-foreground">
          This shared folder is empty.
        </div>
      )}
    </>
  );
}
