import { Show, createSignal, createEffect, onCleanup, type ParentProps } from "solid-js";
import { Spinner } from "@/shared/ui/spinner";
import { AlertCircleIcon, WifiOffIcon } from "lucide-solid";
import { currentWorkspaceId } from "@/entities/workspace";
import {
  getDocumentError,
  needsReauth,
  completeReauth,
  getRollbackWarning,
  approveRollback,
  initializeDocumentPanel,
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
import { PasswordReentryDialog } from "@/features/auth";

interface DocumentPanelShellProps {
  documentId: string;
}

const EXPORTABLE_ERROR_MESSAGES = new Set([
  "document_not_found",
  "not_a_member",
  "permission_denied",
]);

export function DocumentPanelShell(props: ParentProps<DocumentPanelShellProps>) {
  const [isLoading, setIsLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [isOfflineCached, setIsOfflineCached] = createSignal(false);
  const [isAccessRevoked, setIsAccessRevoked] = createSignal(false);
  const [isDocumentDeleted, setIsDocumentDeleted] = createSignal(false);
  const [hasWarmCachePreview, setHasWarmCachePreview] = createSignal(false);

  createEffect(() => {
    const cleanup = initializeDocumentPanel(props.documentId, currentWorkspaceId(), {
      setError,
      setHasWarmCachePreview,
      setIsAccessRevoked,
      setIsDocumentDeleted,
      setIsLoading,
      setIsOfflineCached,
    });

    onCleanup(cleanup);
  });

  const runtimeError = () => getDocumentError(props.documentId);
  const displayError = () => error() || runtimeError();
  const canExportCachedContent = () =>
    isAccessRevoked() || isDocumentDeleted() || EXPORTABLE_ERROR_MESSAGES.has(displayError() ?? "");

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
            <Show when={canExportCachedContent()}>
              <Button
                variant="outline"
                size="sm"
                onClick={async () => {
                  const { Notice } = await import("@/shared/lib/notice");
                  try {
                    const { recoverDocumentFromCache } =
                      await import("@/shared/lib/offline/cache/manager/recover");
                    const recovered = await recoverDocumentFromCache(props.documentId);
                    if (!recovered) {
                      new Notice("No cached content available");
                      return;
                    }
                    const text = recovered.yDoc.getText("content").toString();
                    recovered.yDoc.destroy();
                    try {
                      await navigator.clipboard.writeText(text);
                      new Notice("Content copied to clipboard");
                    } catch {
                      new Notice("Failed to copy to clipboard");
                    }
                  } catch {
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
          when={!isLoading() || hasWarmCachePreview()}
          fallback={
            <div class="flex items-center justify-center h-full bg-background">
              <Spinner class="size-6" />
            </div>
          }
        >
          <div class="relative flex h-full flex-col">
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
            <div class="relative min-h-0 flex-1">
              <div
                class="h-full"
                inert={isLoading() && hasWarmCachePreview()}
                aria-busy={isLoading() && hasWarmCachePreview() ? "true" : "false"}
              >
                {props.children}
              </div>
              <Show when={isLoading() && hasWarmCachePreview()}>
                <div class="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 bg-background/55 backdrop-blur-[1px]">
                  <Spinner class="size-5" />
                  <p class="text-xs text-muted-foreground">
                    Showing cached content while loading the latest version...
                  </p>
                </div>
              </Show>
            </div>
          </div>
        </Show>
      </Show>
    </>
  );
}
