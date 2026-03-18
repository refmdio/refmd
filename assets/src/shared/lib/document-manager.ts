import { Events, type EventRef } from "./events";

export interface EditorLike {
  getValue(): string;
}

export interface DocumentView {
  id: string;
  title: string;
  editor: EditorLike;
}

export interface DocumentContent {
  id: string;
  title: string;
  text: string;
}

export interface DocumentInfo {
  id: string;
  title: string;
  parentId: string | null;
  docType: "document" | "folder";
  archivedAt: string | null;
}

export interface PanelWorkspaceOps {
  openDocument: (doc: { id: string; title?: string }) => void;
  addToTile: (doc: { id: string; title?: string }) => void;
  closePanel: (panelId: string) => void;
  focusedDocumentId: () => string | null;
}

type QueryClientLike = {
  getQueryData: <T>(key: unknown[]) => T | undefined;
};

type DocumentsQueryData = {
  documents: Array<{
    id: string;
    title: string;
    doc_type: string;
    parent_id: string | null;
    archived_at: string | null;
  }>;
};

export class DocumentManagerImpl extends Events {
  private ops: PanelWorkspaceOps | null = null;
  private queryClient: QueryClientLike | null = null;
  private getWorkspaceId: (() => string | null) | null = null;
  private getTitleFn: ((doc: { id: string }) => string) | null = null;
  private getActiveEditorFn: (() => EditorLike | null) | null = null;
  private getEditorForDocFn: ((docId: string) => EditorLike | null) | null = null;
  private getDocTextFn: ((id: string) => string | null) | null = null;
  private createDocumentFn:
    | ((wsId: string, title: string, parentId: string | null) => Promise<string>)
    | null = null;

  init(
    ops: PanelWorkspaceOps,
    queryClient: QueryClientLike,
    getWorkspaceId: () => string | null,
    getActiveEditorFn: () => EditorLike | null,
    getEditorForDocFn: (docId: string) => EditorLike | null,
  ): void {
    this.ops = ops;
    this.queryClient = queryClient;
    this.getWorkspaceId = getWorkspaceId;
    this.getActiveEditorFn = getActiveEditorFn;
    this.getEditorForDocFn = getEditorForDocFn;
  }

  setTitleResolver(fn: (doc: { id: string }) => string): void {
    this.getTitleFn = fn;
  }

  setDocTextResolver(fn: (id: string) => string | null): void {
    this.getDocTextFn = fn;
  }

  setCreateDocumentFn(
    fn: (wsId: string, title: string, parentId: string | null) => Promise<string>,
  ): void {
    this.createDocumentFn = fn;
  }

  async createDocument(title: string, parentId?: string | null): Promise<string> {
    const wsId = this.getWorkspaceId?.();
    if (!wsId || !this.createDocumentFn) throw new Error("Cannot create document");
    return this.createDocumentFn(wsId, title, parentId ?? null);
  }

  getActiveDocument(): DocumentView | null {
    const docId = this.ops?.focusedDocumentId();
    if (!docId) return null;

    const docs = this.getDocumentList();
    const doc = docs.find((d) => d.id === docId);
    const title = doc?.title ?? "Untitled";
    const editor = this.getActiveEditorFn?.() ?? this.getEditorForDocFn?.(docId) ?? null;
    if (!editor) return null;

    return { id: docId, title, editor };
  }

  async getDocumentById(id: string): Promise<DocumentContent | null> {
    const wsId = this.getWorkspaceId?.();
    if (!wsId || !this.queryClient) return null;

    const data = this.queryClient.getQueryData<DocumentsQueryData>(["documents", wsId]);
    const doc = data?.documents?.find((d) => d.id === id);
    if (!doc) return null;

    const title = this.getTitleFn?.({ id }) ?? doc.title;
    const text = this.getDocTextFn?.(id);
    if (text == null) return null;
    return { id, title, text };
  }

  getDocumentList(): DocumentInfo[] {
    const wsId = this.getWorkspaceId?.();
    if (!wsId || !this.queryClient) return [];

    const data = this.queryClient.getQueryData<DocumentsQueryData>(["documents", wsId]);
    if (!data?.documents) return [];

    return data.documents.map((d) => ({
      id: d.id,
      title: this.getTitleFn?.({ id: d.id }) ?? d.title,
      parentId: d.parent_id,
      docType: d.doc_type as "document" | "folder",
      archivedAt: d.archived_at,
    }));
  }

  openDocument(id: string, title?: string): void {
    const resolvedTitle = title ?? this.getTitleFn?.({ id }) ?? "Untitled";
    this.ops?.openDocument({ id, title: resolvedTitle });
  }

  getActiveDocumentText(): string | null {
    const docId = this.ops?.focusedDocumentId();
    if (!docId) return null;
    return this.getDocTextFn?.(docId) ?? null;
  }

  private pendingOpens = new Map<string, string>();

  notifyDocumentOpen(docId: string, title: string): void {
    const editor = this.getEditorForDocFn?.(docId) ?? this.getActiveEditorFn?.() ?? null;
    if (!editor) {
      this.pendingOpens.set(docId, title);
      return;
    }
    this.pendingOpens.delete(docId);
    this.trigger("document-open", { id: docId, title, editor } as DocumentView);
  }

  flushPendingOpens(): void {
    for (const [docId, title] of this.pendingOpens) {
      const editor = this.getEditorForDocFn?.(docId) ?? this.getActiveEditorFn?.() ?? null;
      if (editor) {
        this.pendingOpens.delete(docId);
        this.trigger("document-open", { id: docId, title, editor } as DocumentView);
      }
    }
  }

  notifyDocumentClose(docId: string): void {
    this.trigger("document-close", docId);
  }

  notifyDocumentChange(): void {
    const doc = this.getActiveDocument();
    if (doc) {
      this.trigger("document-change", doc);
    }
  }

  notifyDocumentChangeFor(docId: string, editor: EditorLike | null): void {
    const docs = this.getDocumentList();
    const doc = docs.find((d) => d.id === docId);
    const title = doc?.title ?? "Untitled";
    const resolvedEditor = editor ?? this.getEditorForDocFn?.(docId) ?? null;
    if (!resolvedEditor) return;
    this.trigger("document-change", { id: docId, title, editor: resolvedEditor } as DocumentView);
  }

  notifyDocumentCreate(docId: string): void {
    this.trigger("document-create", docId);
  }

  notifyDocumentDelete(docId: string): void {
    this.trigger("document-delete", docId);
  }

  notifyDocumentRename(docId: string, oldTitle: string): void {
    this.trigger("document-rename", docId, oldTitle);
  }

  on(event: "document-open", cb: (doc: DocumentView) => void): EventRef;
  on(event: "document-close", cb: (docId: string) => void): EventRef;
  on(event: "document-change", cb: (doc: DocumentView) => void): EventRef;
  on(event: "document-create", cb: (docId: string) => void): EventRef;
  on(event: "document-delete", cb: (docId: string) => void): EventRef;
  on(event: "document-rename", cb: (docId: string, oldTitle: string) => void): EventRef;
  on(event: string, cb: (...data: any[]) => any, ctx?: unknown): EventRef {
    return super.on(event, cb, ctx);
  }
}

export const documentManager = new DocumentManagerImpl();
