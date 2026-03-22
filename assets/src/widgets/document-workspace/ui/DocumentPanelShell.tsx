import { Show, createSignal, createEffect, onCleanup, type ParentProps } from "solid-js";
import { Spinner } from "@/shared/ui/spinner";
import { AlertCircleIcon } from "lucide-solid";
import { currentWorkspaceId } from "@/entities/workspace";
import {
  acquireDocumentState,
  releaseDocumentState,
  getDocumentState,
  getDocumentError,
  initializeDocumentSync,
} from "@/features/editor";

interface DocumentPanelShellProps {
  documentId: string;
}

export function DocumentPanelShell(props: ParentProps<DocumentPanelShellProps>) {
  const [isLoading, setIsLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);

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
      } catch (err) {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : "Failed to load document";
        setError(msg);
        const state = getDocumentState(documentId);
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

  return (
    <Show
      when={!displayError()}
      fallback={
        <div class="flex flex-col items-center justify-center h-full bg-background">
          <AlertCircleIcon class="size-6 text-destructive" />
          <p class="mt-2 text-sm text-destructive">{displayError()}</p>
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
        {props.children}
      </Show>
    </Show>
  );
}
