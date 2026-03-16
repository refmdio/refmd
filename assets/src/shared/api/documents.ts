import { client, throwIfError } from "./core";
import type { components } from "./schema";

export const documentsApi = {
  list: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/documents", {
        params: { query: { workspace_id: workspaceId } },
      }),
    ),

  get: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}", {
        params: { path: { document_id: documentId } },
      }),
    ),

  create: async (body: components["schemas"]["CreateDocumentRequest"]) =>
    throwIfError(
      await client.POST("/api/documents", {
        body,
      }),
    ),

  update: async (documentId: string, body: components["schemas"]["UpdateDocumentRequest"]) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}", {
        params: { path: { document_id: documentId } },
        body,
      }),
    ),

  delete: async (documentId: string) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}", {
        params: { path: { document_id: documentId } },
      }),
    ),

  archive: async (documentId: string) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/archive", {
        params: { path: { document_id: documentId } },
      }),
    ),

  unarchive: async (documentId: string) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/unarchive", {
        params: { path: { document_id: documentId } },
      }),
    ),

  reorder: async (body: components["schemas"]["ReorderDocumentRequest"]) =>
    throwIfError(
      await client.PATCH("/api/documents/reorder", {
        body,
      }),
    ),
};
