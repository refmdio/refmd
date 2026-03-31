import { Show, createSignal, createEffect, onCleanup, lazy, type ParentProps } from "solid-js";
import { Spinner } from "@/shared/ui/spinner";
import { AlertCircleIcon, WifiOffIcon } from "lucide-solid";
import { currentWorkspaceId } from "@/entities/workspace";
import {
  acquireDocumentState,
  releaseDocumentState,
  getDocumentState,
  getDocumentError,
  initializeDocumentSync,
  initializeDocumentFromCache,
  needsReauth,
  completeReauth,
  requestReauth,
  getRollbackWarning,
  approveRollback,
} from "@/features/editor";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";

const PasswordReentryDialog = lazy(() => import("@/features/auth/password-reentry-dialog"));

interface DocumentPanelShellProps {
  documentId: string;
}

export function DocumentPanelShell(props: ParentProps<DocumentPanelShellProps>) {
  const [isLoading, setIsLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [isOfflineCached, setIsOfflineCached] = createSignal(false);
  const [isAccessRevoked, setIsAccessRevoked] = createSignal(false);

  createEffect(() => {
    const documentId = props.documentId;
    const workspaceId = currentWorkspaceId();
    if (!workspaceId) {
      setError("No workspace selected");
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setError(null);
    setIsOfflineCached(false);

    let cancelled = false;

    (async () => {
      try {
        await acquireDocumentState(documentId, workspaceId);

        const state = getDocumentState(documentId);
        if (!state || cancelled) return;

        // If already initialized (shared with another panel), skip sync init
        if (!state.initialized && !state.initPromise) {
          state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
        }

        if (state.initPromise) {
          await state.initPromise;
        }

        if (cancelled) return;

        if (state.error) {
          setError(state.error);
        }
        if (state.loadedFromOfflineCache) {
          setIsOfflineCached(true);
        }
      } catch (err) {
        if (cancelled) return;

        // Attempt cache recovery when server sync fails (offline or server unreachable).
        // Do NOT recover for security failures (proof chain, verification) — those are fail-closed.
        const errMsg = err instanceof Error ? err.message : String(err);
        const isSecurityFailure =
          errMsg.includes("rollback attack") ||
          errMsg.includes("verification_failed") ||
          errMsg.includes("Version regression") ||
          errMsg.includes("Snapshot proof chain") ||
          errMsg.includes("Proof chain");
        const isAuthFailure = errMsg.includes("unauthorized");
        const isAccessDenied =
          errMsg.includes("not_a_member") || errMsg.includes("permission_denied");
        const isDeleted = errMsg.includes("document_not_found");
        const state = getDocumentState(documentId);
        if (state && isAuthFailure) {
          try {
            await requestReauth(documentId);
            if (cancelled) return;

            state.error = null;
            state.initPromise = initializeDocumentSync(documentId, workspaceId, state);
            await state.initPromise;

            if (cancelled) return;

            setError(state.error);
            setIsOfflineCached(state.loadedFromOfflineCache);
            setIsLoading(false);
            return;
          } catch (retryError) {
            const retryMessage =
              retryError instanceof Error ? retryError.message : "Failed to load document";
            setError(retryMessage);
            state.error = retryMessage;
            setIsLoading(false);
            return;
          }
        }

        // Deleted documents: skip cache recovery, show error + export (design requirement)
        if (state && !state.initialized && !isSecurityFailure && !isDeleted) {
          try {
            const recovered = await initializeDocumentFromCache(documentId, workspaceId, state);
            if (recovered && !cancelled) {
              // For access-denied cases, stop auto-sync and mark read-only
              if (isAccessDenied) {
                if (state.autoSync) {
                  state.autoSync.dispose();
                  state.autoSync = null;
                }
                state.readOnly = true;
                setIsOfflineCached(true);
                setIsAccessRevoked(true);
                setError(null);
                setIsLoading(false);
                return;
              }
              setIsOfflineCached(true);
              setError(null);
              setIsLoading(false);
              return;
            }
          } catch {
            // Recovery failed, fall through to error
          }
        }

        const msg = err instanceof Error ? err.message : "Failed to load document";
        setError(msg);
        if (state) state.error = msg;
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    onCleanup(() => {
      cancelled = true;
      releaseDocumentState(documentId);
    });
  });

  const runtimeError = () => getDocumentError(props.documentId);
  const displayError = () => error() || runtimeError();

  const showReauth = () => needsReauth(props.documentId);
  const rollbackWarning = () => getRollbackWarning(props.documentId);

  return (
    <>
      <PasswordReentryDialog
        open={showReauth()}
        onComplete={() => completeReauth(props.documentId)}
      />
      <Dialog open={!!rollbackWarning()}>
        <DialogContent showCloseButton={false}>
          <DialogHeader>
            <DialogTitle>State Inconsistency Detected</DialogTitle>
            <DialogDescription>
              The server returned data that appears to be older than what was previously observed.
              This may indicate a server issue. Do you want to continue?
            </DialogDescription>
          </DialogHeader>
          <p class="text-sm text-muted-foreground">{rollbackWarning()}</p>
          <DialogFooter>
            <Button onClick={() => approveRollback(props.documentId)}>Continue</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Show
        when={!displayError()}
        fallback={
          <div class="flex flex-col items-center justify-center h-full bg-background gap-3">
            <AlertCircleIcon class="size-6 text-destructive" />
            <p class="text-sm text-destructive">{displayError()}</p>
            <Show
              when={
                displayError()?.includes("not_found") || displayError()?.includes("not_a_member")
              }
            >
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  try {
                    const { recoverDocumentFromCache } =
                      await import("@/shared/lib/offline/cache-manager");
                    const recovered = await recoverDocumentFromCache(props.documentId);
                    if (recovered) {
                      const text = recovered.yDoc.getText("content").toString();
                      recovered.yDoc.destroy();
                      await navigator.clipboard.writeText(text);
                      const { Notice } = await import("@/shared/lib/notice");
                      new Notice("Content copied to clipboard");
                    }
                  } catch {
                    const { Notice } = await import("@/shared/lib/notice");
                    new Notice("No cached content available");
                  }
                }}
              >
                Export cached content
              </Button>
            </Show>
          </div>
        }
      >
        <Show
          when={!isLoading()}
          fallback={
            <div class="flex items-center justify-center h-full bg-background">
              <Spinner class="size-6" />
            </div>
          }
        >
          <Show when={isOfflineCached()}>
            <div class="flex items-center gap-1.5 px-3 py-1 text-xs bg-yellow-50 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 border-b border-yellow-200 dark:border-yellow-800">
              <WifiOffIcon class="size-3" />
              <span>
                {isAccessRevoked()
                  ? "Read-only — workspace access revoked"
                  : "Editing offline — changes will sync when reconnected"}
              </span>
            </div>
          </Show>
          {props.children}
        </Show>
      </Show>
    </>
  );
}
