import { Show, createSignal, createEffect, onCleanup, type ParentProps } from "solid-js";
import { AlertCircleIcon } from "lucide-solid";
import { currentWorkspaceId } from "@/entities/workspace";
import {
  getDocumentError,
  completeReauth,
  needsReauth,
  initializeDocumentTile,
} from "@/features/editor";
import { Button } from "@/shared/ui/button";
import { PasswordReentryDialog } from "@/features/auth";
import { offlineMode } from "@/shared/lib/offline/offline-state";
import { DocumentTilePhaseContent } from "./DocumentTilePhaseContent";
import { readInitializedDocumentPreviewText } from "./document-preview";

interface DocumentTileShellProps {
  documentId: string;
  showDialogs?: boolean;
  stateKey: string;
  workspaceId?: string | null;
}

const EXPORTABLE_ERROR_MESSAGES = new Set([
  "document_not_found",
  "not_a_member",
  "permission_denied",
]);
const DOCUMENT_LOADING_PREVIEW_MAX_CHARS = 64 * 1024;
const SHARE_CONTENT_VISIBLE_EVENT = "refmd:share-content-visible";
const REMOTE_CONTENT_READY_EVENT = "refmd:document-remote-content-ready";
const dismissedReadyPreviewStateKeys = new Set<string>();

function truncatePreviewText(text: string): string {
  return text.length > DOCUMENT_LOADING_PREVIEW_MAX_CHARS
    ? text.slice(0, DOCUMENT_LOADING_PREVIEW_MAX_CHARS)
    : text;
}

function recordDocumentTilePerf(event: string, detail: Record<string, unknown>): void {
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

function notifyShareContentVisible(detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.location.pathname.startsWith("/share/")) return;
  window.dispatchEvent(new CustomEvent(SHARE_CONTENT_VISIBLE_EVENT, { detail }));
}

function normalizeVisibleText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function expectedRenderedTokens(markdownText: string): string[] {
  return markdownText
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) =>
      line
        .trim()
        .replace(/^#{1,6}\s+/, "")
        .replace(/^[-*+]\s+/, "")
        .replace(/^\d+\.\s+/, "")
        .trim(),
    )
    .filter((line) => line.length > 0);
}

function isVisibleElement(node: HTMLElement): boolean {
  const rect = node.getBoundingClientRect();
  const style = window.getComputedStyle(node);
  return (
    rect.width > 0 &&
    rect.height > 0 &&
    style.display !== "none" &&
    style.visibility !== "hidden" &&
    style.opacity !== "0"
  );
}

function readVisibleEditorSurfaceText(): string {
  const fragments: string[] = [];
  for (const editor of document.querySelectorAll<HTMLElement>(
    ".cm-content[contenteditable='true']",
  )) {
    if (!isVisibleElement(editor)) continue;
    const lines = [...editor.querySelectorAll<HTMLElement>(".cm-line")].map(
      (line) => line.textContent ?? "",
    );
    fragments.push(lines.length > 0 ? lines.join("\n") : (editor.textContent ?? ""));
  }
  for (const editor of document.querySelectorAll<HTMLElement>(
    ".ProseMirror[contenteditable='true'], [role='textbox'][contenteditable='true']",
  )) {
    if (!isVisibleElement(editor)) continue;
    fragments.push(editor.innerText || editor.textContent || "");
  }
  for (const editor of document.querySelectorAll<HTMLTextAreaElement>("textarea:not([readonly])")) {
    if (!isVisibleElement(editor)) continue;
    fragments.push(editor.value);
  }
  return normalizeVisibleText(fragments.join("\n"));
}

function DocumentLoadingFallback(props: { stateKey: string }) {
  const [previewText, setPreviewText] = createSignal("");
  let previewRefreshTimer: ReturnType<typeof setInterval> | null = null;

  const clearPreviewRefreshTimer = () => {
    if (previewRefreshTimer === null) return;
    clearInterval(previewRefreshTimer);
    previewRefreshTimer = null;
  };
  const applyPreviewText = (text: string) => {
    const next = truncatePreviewText(text);
    setPreviewText(next);
    if (next.trim().length > 0) {
      notifyShareContentVisible({
        source: "document-loading-fallback",
        stateKey: props.stateKey,
        previewTextLength: next.length,
      });
      clearPreviewRefreshTimer();
    }
  };
  const refreshPreviewText = () => {
    const next = readInitializedDocumentPreviewText(props.stateKey);
    if (next.text.trim().length > 0) {
      applyPreviewText(next.text);
      return;
    }
    if (next.initialized) clearPreviewRefreshTimer();
  };

  createEffect(() => {
    refreshPreviewText();
    if (typeof window === "undefined" || previewRefreshTimer !== null) return;
    previewRefreshTimer = window.setInterval(refreshPreviewText, 50);
  });
  onCleanup(clearPreviewRefreshTimer);

  const visiblePreviewText = () => (previewText().trim().length > 0 ? previewText() : "");

  return (
    <Show
      when={visiblePreviewText()}
      fallback={
        <div class="flex items-center justify-center h-full bg-background">
          <DocumentTilePhaseContent
            label="Mounting document editor"
            detail="Preparing encrypted content, sync state, and editor DOM."
            value={68}
          />
        </div>
      }
    >
      <div
        class="h-full overflow-auto bg-background px-6 py-5 whitespace-pre-wrap break-words text-sm leading-6 text-foreground"
        data-refmd-content-preview="true"
      >
        {previewText()}
      </div>
    </Show>
  );
}

function DocumentReadyPreviewOverlay(props: { stateKey: string; active: boolean }) {
  const [previewText, setPreviewText] = createSignal("");
  const [previewMode, setPreviewMode] = createSignal<"initial" | "remote">("initial");
  let previewRefreshTimer: ReturnType<typeof setInterval> | null = null;
  let renderWatchFrame: number | null = null;
  let visibleSince: number | null = null;

  const clearPreviewRefreshTimer = () => {
    if (previewRefreshTimer === null) return;
    clearInterval(previewRefreshTimer);
    previewRefreshTimer = null;
  };
  const clearRenderWatchFrame = () => {
    if (renderWatchFrame === null) return;
    cancelAnimationFrame(renderWatchFrame);
    renderWatchFrame = null;
  };
  const dismissPreview = (reason: string) => {
    dismissedReadyPreviewStateKeys.add(props.stateKey);
    if (previewText().trim().length > 0) {
      recordDocumentTilePerf("document_ready_preview_overlay_cleared", {
        reason,
        stateKey: props.stateKey,
      });
    }
    setPreviewText("");
    setPreviewMode("initial");
    visibleSince = null;
    clearPreviewRefreshTimer();
    clearRenderWatchFrame();
  };
  const isEditorInteractionTarget = (target: EventTarget | null) =>
    target instanceof Element &&
    !!target.closest(
      ".cm-editor, .cm-content, .ProseMirror, [data-testid='document-editor'], [role='textbox']",
    );
  const handleEditorInteraction = (event: Event) => {
    if (!props.active || !isEditorInteractionTarget(event.target)) return;
    if (previewMode() === "remote" && !editorAlreadyRendersPreview()) return;
    dismissPreview("editor-interaction");
  };
  const editorAlreadyRendersPreview = () => {
    const tokens = expectedRenderedTokens(previewText());
    if (tokens.length === 0) return false;
    const rendered = readVisibleEditorSurfaceText();
    return tokens.every((token) => rendered.includes(normalizeVisibleText(token)));
  };
  const editorCanReceiveInput = () =>
    document.querySelector(
      ".cm-content[contenteditable='true'], .ProseMirror[contenteditable='true'], [role='textbox'][contenteditable='true'], textarea:not([readonly])",
    ) !== null;
  const refreshPreviewText = () => {
    if (!props.active) {
      if (previewText().trim().length > 0) {
        recordDocumentTilePerf("document_ready_preview_overlay_cleared", {
          reason: "inactive",
          stateKey: props.stateKey,
        });
      }
      setPreviewText("");
      visibleSince = null;
      clearPreviewRefreshTimer();
      return;
    }
    if (dismissedReadyPreviewStateKeys.has(props.stateKey) && previewMode() !== "remote") {
      setPreviewText("");
      visibleSince = null;
      clearPreviewRefreshTimer();
      return;
    }
    if (previewText().trim().length > 0) {
      clearPreviewRefreshTimer();
      return;
    }
    const next = readInitializedDocumentPreviewText(props.stateKey);
    if (next.text.trim().length > 0) {
      setPreviewText(truncatePreviewText(next.text));
      setPreviewMode("initial");
      visibleSince = performance.now();
      recordDocumentTilePerf("document_ready_preview_overlay_visible", {
        previewTextLength: next.text.length,
        stateKey: props.stateKey,
      });
      notifyShareContentVisible({
        source: "document-ready-preview-overlay",
        stateKey: props.stateKey,
        previewTextLength: next.text.length,
      });
      clearPreviewRefreshTimer();
      return;
    }
    if (next.initialized) clearPreviewRefreshTimer();
  };
  const showRemotePreview = () => {
    if (!props.active) return;
    if (editorCanReceiveInput()) return;
    const next = readInitializedDocumentPreviewText(props.stateKey);
    if (next.text.trim().length === 0) return;
    if (editorAlreadyRendersPreview()) return;
    setPreviewText(truncatePreviewText(next.text));
    setPreviewMode("remote");
    visibleSince = performance.now();
    recordDocumentTilePerf("document_ready_preview_overlay_visible", {
      previewTextLength: next.text.length,
      reason: "remote-content-ready",
      stateKey: props.stateKey,
    });
    notifyShareContentVisible({
      source: "document-ready-preview-overlay",
      stateKey: props.stateKey,
      previewTextLength: next.text.length,
    });
    clearPreviewRefreshTimer();
  };
  const handleRemoteContentReady = (event: Event) => {
    const detail = (event as CustomEvent<{ stateKey?: string }>).detail;
    if (detail?.stateKey !== props.stateKey) return;
    showRemotePreview();
  };
  const watchRenderedEditor = () => {
    clearRenderWatchFrame();
    const check = () => {
      renderWatchFrame = null;
      if (!props.active || previewText().trim().length === 0) return;
      const hasBeenVisible = visibleSince !== null && performance.now() - visibleSince >= 250;
      const isRemotePreview = previewMode() === "remote";
      if (editorAlreadyRendersPreview()) {
        dismissPreview("editor-rendered");
        return;
      }
      if (!isRemotePreview && hasBeenVisible && editorCanReceiveInput()) {
        dismissPreview("editor-interactive");
        return;
      }
      renderWatchFrame = requestAnimationFrame(check);
    };
    renderWatchFrame = requestAnimationFrame(check);
  };

  createEffect(() => {
    refreshPreviewText();
    if (
      typeof window === "undefined" ||
      !props.active ||
      previewText().trim().length > 0 ||
      previewRefreshTimer !== null
    ) {
      return;
    }
    previewRefreshTimer = window.setInterval(refreshPreviewText, 25);
  });

  createEffect(() => {
    if (typeof window === "undefined" || !props.active || previewText().trim().length === 0) {
      clearRenderWatchFrame();
      return;
    }
    watchRenderedEditor();
  });

  onCleanup(() => {
    clearPreviewRefreshTimer();
    clearRenderWatchFrame();
  });

  if (typeof window !== "undefined") {
    window.addEventListener("pointerdown", handleEditorInteraction, true);
    window.addEventListener("focusin", handleEditorInteraction, true);
    window.addEventListener("keydown", handleEditorInteraction, true);
    window.addEventListener(REMOTE_CONTENT_READY_EVENT, handleRemoteContentReady);
    onCleanup(() => {
      window.removeEventListener("pointerdown", handleEditorInteraction, true);
      window.removeEventListener("focusin", handleEditorInteraction, true);
      window.removeEventListener("keydown", handleEditorInteraction, true);
      window.removeEventListener(REMOTE_CONTENT_READY_EVENT, handleRemoteContentReady);
    });
  }

  return (
    <Show when={props.active && previewText().trim().length > 0}>
      <div
        class="pointer-events-none absolute inset-0 z-20 overflow-auto bg-background px-6 py-5 whitespace-pre-wrap break-words text-sm leading-6 text-foreground"
        data-refmd-content-preview="true"
      >
        {previewText()}
      </div>
    </Show>
  );
}

export function DocumentTileShell(props: ParentProps<DocumentTileShellProps>) {
  const [isLoading, setIsLoading] = createSignal(true);
  const [error, setError] = createSignal<string | null>(null);
  const [_isOfflineCached, setIsOfflineCached] = createSignal(false);
  const [isAccessRevoked, setIsAccessRevoked] = createSignal(false);
  const [isDocumentDeleted, setIsDocumentDeleted] = createSignal(false);
  const [hasWarmCachePreview, setHasWarmCachePreview] = createSignal(false);

  createEffect(() => {
    const cleanup = initializeDocumentTile(
      props.documentId,
      props.workspaceId ?? currentWorkspaceId(),
      {
        setError,
        setHasWarmCachePreview,
        setIsAccessRevoked,
        setIsDocumentDeleted,
        setIsLoading,
        setIsOfflineCached,
      },
      props.stateKey,
    );

    onCleanup(cleanup);
  });

  const runtimeError = () => getDocumentError(props.stateKey);
  const displayError = () => error() || runtimeError();
  const canExportCachedContent = () =>
    isAccessRevoked() || isDocumentDeleted() || EXPORTABLE_ERROR_MESSAGES.has(displayError() ?? "");

  const showReauth = () => needsReauth(props.stateKey);
  const showDialogs = () => props.showDialogs ?? true;
  const showWarmCacheLoadingOverlay = () => isLoading() && hasWarmCachePreview() && !offlineMode();

  return (
    <>
      <PasswordReentryDialog
        open={showDialogs() && showReauth()}
        onComplete={() => completeReauth(props.stateKey)}
      />
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
          fallback={<DocumentLoadingFallback stateKey={props.stateKey} />}
        >
          <div class="relative h-full">
            <div
              class="h-full"
              inert={showWarmCacheLoadingOverlay()}
              aria-busy={showWarmCacheLoadingOverlay() ? "true" : "false"}
            >
              {props.children}
            </div>
            <DocumentReadyPreviewOverlay
              stateKey={props.stateKey}
              active={!isLoading() && !showWarmCacheLoadingOverlay()}
            />
            <Show when={showWarmCacheLoadingOverlay()}>
              <div class="absolute inset-0 z-10 flex items-center justify-center bg-background/55 p-6 backdrop-blur-[1px]">
                <DocumentTilePhaseContent
                  label="Refreshing document content"
                  detail="Showing cached content while syncing the latest version."
                  value={82}
                  class="max-w-xs"
                />
              </div>
            </Show>
          </div>
        </Show>
      </Show>
    </>
  );
}
