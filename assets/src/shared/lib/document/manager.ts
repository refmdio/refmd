import type { EventRef } from "../events";

export interface EditorLike {
  getValue(): string;
  setValue?(value: string): void;
  replaceSelection?(text: string): void;
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
  release: () => void;
}

export interface DocumentInfo {
  id: string;
  title: string;
  workspaceId: string;
  parentId: string | null;
  docType: "document" | "folder";
  archivedAt: string | null;
  canSyncPublication: boolean;
}

export interface PanelWorkspaceOps {
  focusedDocumentId: () => string | null;
}

type QueryClientLike = {
  getQueryData: <T>(key: unknown[]) => T | undefined;
};

interface DocumentStateLike {
  initialized: boolean;
  initPromise: Promise<void> | null;
  refCount: number;
  yDoc: {
    getText(name: string): {
      toString(): string;
    };
  };
}

export interface DocumentStateDependencies {
  acquireDocumentState(documentId: string, workspaceId: string): Promise<unknown>;
  getDocumentState(documentId: string): DocumentStateLike | undefined;
  releaseDocumentState(documentId: string): void;
  initializeDocumentSync(
    documentId: string,
    workspaceId: string,
    state: DocumentStateLike,
  ): Promise<void>;
}

export interface DocumentQueries {
  getActiveDocument(): DocumentView | null;
  getDocumentById(id: string): Promise<DocumentContent | null>;
  getDocumentList(): DocumentInfo[];
  getActiveDocumentText(): string | null;
}

export interface DocumentCommandService {
  openDocument(id: string): void;
  createDocument(title: string, parentId?: string | null): Promise<string>;
}

interface DocumentEventSource {
  on(event: "document-open", cb: (doc: DocumentView) => void): EventRef;
  on(event: "document-close", cb: (docId: string) => void): EventRef;
  on(event: "document-change", cb: (doc: DocumentView) => void): EventRef;
  on(event: "document-create", cb: (docId: string) => void): EventRef;
  on(event: "document-delete", cb: (docId: string) => void): EventRef;
  on(
    event: "document-rename",
    cb: (docId: string, oldTitle: string, newTitle: string, isPublished: boolean) => void,
  ): EventRef;
  on(event: string, cb: (...data: unknown[]) => unknown, ctx?: unknown): EventRef;
  offref(ref: EventRef): void;
}

export interface DocumentEventDispatcher extends DocumentEventSource {
  flushPendingOpens(): void;
  notifyDocumentOpen(docId: string, title: string): void;
  notifyDocumentClose(docId: string): void;
  notifyDocumentChangeFor(docId: string, editor: EditorLike | null): void;
  notifyDocumentCreate(docId: string): void;
  notifyDocumentDelete(docId: string): void;
  notifyDocumentRename(
    docId: string,
    oldTitle: string,
    newTitle: string,
    isPublished: boolean,
  ): void;
}

export interface DocumentRuntime {
  setTitleResolver(fn: (doc: { id: string }) => string): void;
  setDocTextResolver(fn: (id: string) => string | null): void;
  setOpenDocumentFn(fn: (documentId: string) => void): void;
  setCreateDocumentFn(
    fn: (wsId: string, title: string, parentId: string | null) => Promise<string>,
  ): void;
  init(
    ops: PanelWorkspaceOps,
    queryClient: QueryClientLike,
    getWorkspaceId: () => string | null,
    getActiveEditorFn: () => EditorLike | null,
    getEditorForDocFn: (docId: string) => EditorLike | null,
    documentStateDeps: DocumentStateDependencies,
  ): void;
}

export type AppDocuments = DocumentQueries & DocumentCommandService & DocumentEventSource;

const noopEventRef = {} as EventRef;

const fallbackDocumentEvents: DocumentEventDispatcher = {
  on: () => noopEventRef,
  offref: () => {},
  flushPendingOpens: () => {},
  notifyDocumentOpen: () => {},
  notifyDocumentClose: () => {},
  notifyDocumentChangeFor: () => {},
  notifyDocumentCreate: () => {},
  notifyDocumentDelete: () => {},
  notifyDocumentRename: () => {},
};

const fallbackDocumentRuntime: DocumentRuntime = {
  setTitleResolver: () => {},
  setDocTextResolver: () => {},
  setOpenDocumentFn: () => {},
  setCreateDocumentFn: () => {},
  init: () => {},
};

let documentEventsRef: DocumentEventDispatcher = fallbackDocumentEvents;
let documentRuntimeRef: DocumentRuntime = fallbackDocumentRuntime;

export function registerDocumentInternals(services: {
  documentEvents: DocumentEventDispatcher;
  documentRuntime: DocumentRuntime;
}): void {
  documentEventsRef = services.documentEvents;
  documentRuntimeRef = services.documentRuntime;
}

export function getDocumentEvents(): DocumentEventDispatcher {
  return documentEventsRef;
}

export function getDocumentRuntime(): DocumentRuntime {
  return documentRuntimeRef;
}
