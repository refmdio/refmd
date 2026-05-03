import { createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import {
  enterShareRouteSession,
  leaveShareRouteSession,
  resolveShareFolderRoute,
  type ResolvedShareFolderEntry,
} from "@/features/share";
import { Spinner } from "@/shared/ui/spinner";
import { ShareWorkspaceShell } from "./ShareWorkspaceShell";

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

        if (resolved.kind === "bootstrap-required") {
          pendingFolderToken = null;
          navigate(`/share/${resolved.shareSlug}`, {
            replace: true,
            scroll: false,
          });
          return;
        }

        pendingFolderToken = null;
        resolvedFolderToken = folderToken;
        setFolder(resolved.folder);
        setEntries(resolved.entries);
        setShareSlug(resolved.shareSlug);
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
