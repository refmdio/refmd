import { createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import {
  bootstrapShareParticipantSession,
  enterShareRouteSession,
  leaveShareRouteSession,
  resolveShareFolderRoute,
  ShareRoutePhaseContent,
  type ShareRoutePhase,
  type ResolvedShareFolderEntry,
} from "@/features/share";
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

const SHARE_FOLDER_PROGRESS = {
  resolving: {
    label: "Resolving shared folder",
    detail: "Checking the folder route and share session state.",
    value: 24,
  },
  restoringSession: {
    label: "Restoring anonymous session",
    detail: "Recreating share access material before opening the folder.",
    value: 48,
  },
  resolvingAfterSession: {
    label: "Verifying restored access",
    detail: "Rechecking the folder route with the restored anonymous session.",
    value: 62,
  },
  mountingWorkspace: {
    label: "Mounting shared folder",
    detail: "Rendering the shared folder workspace and entry list.",
    value: 90,
  },
} satisfies Record<string, ShareRoutePhase>;

export function ShareFolderWorkspace(props: { children: JSX.Element }) {
  const navigate = useNavigate();
  const params = useParams<{ folderToken?: string }>();
  const [error, setError] = createSignal<string | null>(null);
  const [folder, setFolder] = createSignal<ResolvedShareFolderEntry | null>(null);
  const [entries, setEntries] = createSignal<ResolvedShareFolderEntry[]>([]);
  const [shareSlug, setShareSlug] = createSignal<string | null>(null);
  const [loaded, setLoaded] = createSignal(false);
  const [progress, setProgress] = createSignal<ShareRoutePhase>(SHARE_FOLDER_PROGRESS.resolving);
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
    setProgress(SHARE_FOLDER_PROGRESS.resolving);
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
            setProgress(SHARE_FOLDER_PROGRESS.restoringSession);
            await bootstrapShareParticipantSession(shareSlug);
            setProgress(SHARE_FOLDER_PROGRESS.resolvingAfterSession);
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
        setProgress(SHARE_FOLDER_PROGRESS.mountingWorkspace);
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
          <ShareRoutePhaseContent phase={progress()} />
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
