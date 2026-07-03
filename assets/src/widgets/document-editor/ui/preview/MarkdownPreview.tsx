import { createEffect, createMemo, createSignal, onCleanup } from "solid-js";
import { acquireYDoc, emitScrollSync, onScrollSync, releaseYDoc } from "@/features/editor";
import { MarkdownView, parseMarkdownView } from "@/shared/lib/markdown/MarkdownView";
import {
  ensureYDocMarkdownText,
  readYDocMarkdownPreview,
} from "../../lib/prosemirror/preview-text";

interface MarkdownPreviewProps {
  stateKey: string;
  scrollGroupId?: string;
}

export function MarkdownPreview(props: MarkdownPreviewProps) {
  const scrollSourceId = `preview-${Math.random().toString(36).slice(2)}`;
  const [markdown, setMarkdown] = createSignal("");
  const root = createMemo(() => parseMarkdownView(markdown()));
  let containerEl: HTMLDivElement | undefined;
  let activeStateKey: string | undefined;
  let cleanupPreview: (() => void) | undefined;
  let unsubScroll: (() => void) | undefined;
  let suppressScroll = false;

  function destroyPreview() {
    cleanupPreview?.();
    cleanupPreview = undefined;
    unsubScroll?.();
    unsubScroll = undefined;
    if (activeStateKey) {
      releaseYDoc(activeStateKey);
      activeStateKey = undefined;
    }
  }

  function createPreview(stateKey: string) {
    if (!containerEl) return;
    if (activeStateKey === stateKey) return;
    if (activeStateKey) destroyPreview();
    const rootEl = containerEl;
    const { yDoc } = acquireYDoc(stateKey);
    const yText = ensureYDocMarkdownText(yDoc);
    const yProseMirror = yDoc.getXmlFragment("prosemirror");
    activeStateKey = stateKey;

    const refreshMarkdown = () => setMarkdown(readYDocMarkdownPreview(yDoc));
    const refreshProseMirrorMarkdown = () => refreshMarkdown();
    refreshMarkdown();
    yText.observe(refreshMarkdown);
    yProseMirror.observeDeep(refreshProseMirrorMarkdown);

    const groupId = props.scrollGroupId;
    const handleScroll = () => {
      if (suppressScroll || !groupId) return;
      const maxScroll = rootEl.scrollHeight - rootEl.clientHeight;
      if (maxScroll <= 0) return;
      emitScrollSync(groupId, rootEl.scrollTop / maxScroll, scrollSourceId);
    };
    rootEl.addEventListener("scroll", handleScroll, { passive: true });

    if (groupId) {
      unsubScroll = onScrollSync(groupId, (ratio, sourceId) => {
        if (sourceId === scrollSourceId) return;
        const maxScroll = rootEl.scrollHeight - rootEl.clientHeight;
        if (maxScroll <= 0) return;
        suppressScroll = true;
        rootEl.scrollTop = ratio * maxScroll;
        requestAnimationFrame(() => {
          suppressScroll = false;
        });
      });
    }

    cleanupPreview = () => {
      yText.unobserve(refreshMarkdown);
      yProseMirror.unobserveDeep(refreshProseMirrorMarkdown);
      rootEl.removeEventListener("scroll", handleScroll);
    };
  }

  createEffect(() => {
    const stateKey = props.stateKey;
    if (activeStateKey === stateKey) return;
    destroyPreview();
    createPreview(stateKey);
  });

  onCleanup(destroyPreview);

  return (
    <div
      ref={(el) => {
        containerEl = el;
        createPreview(props.stateKey);
      }}
      class="h-full overflow-auto bg-background select-text"
      data-testid="markdown-preview"
    >
      <div class="refmd-editor-readable-surface px-[3.25rem] py-4 text-foreground">
        <MarkdownView root={root()} />
      </div>
    </div>
  );
}
