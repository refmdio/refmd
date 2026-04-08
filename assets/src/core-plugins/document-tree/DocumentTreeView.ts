import { ItemView } from "@/shared/lib/workspace/view";
import { renderPluginContent } from "@/shared/lib/plugin/render";
import { DocumentTreePanel } from "@/widgets/sidebar";

export class DocumentTreeView extends ItemView {
  override navigation = false;
  private dispose: (() => void) | null = null;

  getViewType(): string {
    return "document-tree";
  }

  getDisplayText(): string {
    return "Document Tree";
  }

  async onOpen(): Promise<void> {
    this.contentEl.style.height = "100%";
    this.contentEl.style.overflow = "hidden";
    this.contentEl.style.display = "flex";
    this.contentEl.style.flexDirection = "column";
    this.dispose = renderPluginContent(() => DocumentTreePanel(), this.contentEl);
  }

  async onClose(): Promise<void> {
    this.dispose?.();
    this.dispose = null;
  }
}
