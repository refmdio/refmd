import { Events, type EventRef } from "@/shared/lib/events";
import type {
  AppDocuments,
  DocumentCommandService,
  DocumentContent,
  DocumentEventDispatcher,
  DocumentInfo,
  DocumentQueries,
  DocumentRuntime,
  DocumentStateDependencies,
  DocumentView,
  EditorLike,
  PanelWorkspaceOps,
} from "@/shared/lib/document-manager";

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

class DocumentManagerImpl
  extends Events
  implements DocumentQueries, DocumentCommandService, DocumentEventDispatcher, DocumentRuntime
{
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
  private documentStateDeps: DocumentStateDependencies | null = null;
  private pendingOpens = new Map<string, string>();

  init(
    ops: PanelWorkspaceOps,
    queryClient: QueryClientLike,
    getWorkspaceId: () => string | null,
    getActiveEditorFn: () => EditorLike | null,
    getEditorForDocFn: (docId: string) => EditorLike | null,
    documentStateDeps: DocumentStateDependencies,
  ): void {
    this.ops = ops;
    this.queryClient = queryClient;
    this.getWorkspaceId = getWorkspaceId;
    this.getActiveEditorFn = getActiveEditorFn;
    this.getEditorForDocFn = getEditorForDocFn;
    this.documentStateDeps = documentStateDeps;
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
    const doc = docs.find((candidate) => candidate.id === docId);
    const title = doc?.title ?? "Untitled";
    const editor = this.getActiveEditorFn?.() ?? this.getEditorForDocFn?.(docId) ?? null;
    if (!editor) return null;

    return { id: docId, title, editor };
  }

  async getDocumentById(id: string): Promise<DocumentContent | null> {
    const wsId = this.getWorkspaceId?.();
    if (!wsId || !this.queryClient || !this.documentStateDeps) return null;

    const data = this.queryClient.getQueryData<DocumentsQueryData>(["documents", wsId]);
    const doc = data?.documents?.find((candidate) => candidate.id === id);
    if (!doc) return null;

    const title = this.getTitleFn?.({ id }) ?? doc.title;
    const { acquireDocumentState, getDocumentState, releaseDocumentState, initializeDocumentSync } =
      this.documentStateDeps;

    const text = this.getDocTextFn?.(id);
    if (text != null) {
      const cached = getDocumentState(id);
      if (cached) {
        cached.refCount++;
      }
      return { id, title, text, release: () => releaseDocumentState(id) };
    }

    try {
      await acquireDocumentState(id, wsId);
    } catch {
      return null;
    }

    const state = getDocumentState(id);
    if (!state) return null;

    try {
      if (!state.initialized && !state.initPromise) {
        state.initPromise = initializeDocumentSync(id, wsId, state);
      }
      if (state.initPromise) {
        await state.initPromise;
      }
    } catch {
      releaseDocumentState(id);
      return null;
    }

    if (!state.initialized) {
      releaseDocumentState(id);
      return null;
    }

    return {
      id,
      title,
      text: state.yDoc.getText("content").toString(),
      release: () => releaseDocumentState(id),
    };
  }

  getDocumentList(): DocumentInfo[] {
    const wsId = this.getWorkspaceId?.();
    if (!wsId || !this.queryClient) return [];

    const data = this.queryClient.getQueryData<DocumentsQueryData>(["documents", wsId]);
    if (!data?.documents) return [];

    return data.documents.map((doc) => ({
      id: doc.id,
      title: this.getTitleFn?.({ id: doc.id }) ?? doc.title,
      parentId: doc.parent_id,
      docType: doc.doc_type as "document" | "folder",
      archivedAt: doc.archived_at,
    }));
  }

  getActiveDocumentText(): string | null {
    const docId = this.ops?.focusedDocumentId();
    if (!docId) return null;
    return this.getDocTextFn?.(docId) ?? null;
  }

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

  notifyDocumentChangeFor(docId: string, editor: EditorLike | null): void {
    const doc = this.getDocumentList().find((candidate) => candidate.id === docId);
    const resolvedEditor = editor ?? this.getEditorForDocFn?.(docId) ?? null;
    if (!resolvedEditor) return;

    this.trigger("document-change", {
      id: docId,
      title: doc?.title ?? "Untitled",
      editor: resolvedEditor,
    } as DocumentView);
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
  on(event: string, cb: (...data: unknown[]) => unknown, ctx?: unknown): EventRef {
    return super.on(event, cb, ctx);
  }
}

const documentManager = new DocumentManagerImpl();
export const appDocuments: AppDocuments = documentManager;
export const documentQueries: DocumentQueries = documentManager;
export const documentCommands: DocumentCommandService = documentManager;
export const documentEvents: DocumentEventDispatcher = documentManager;
export const documentRuntime: DocumentRuntime = documentManager;
