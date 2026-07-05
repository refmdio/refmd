import { createMemo } from "solid-js";
import { MarkdownView, parseMarkdownView } from "@/shared/lib/markdown/markdown-view";

import "@/shared/lib/markdown/markdown-surface.css";

interface DocumentMarkdownPreviewSurfaceProps {
  markdown: string;
}

export function DocumentMarkdownPreviewSurface(props: DocumentMarkdownPreviewSurfaceProps) {
  const root = createMemo(() => parseMarkdownView(props.markdown));

  return (
    <div class="refmd-editor-readable-surface px-[3.25rem] py-4 text-foreground">
      <MarkdownView root={root()} />
    </div>
  );
}
