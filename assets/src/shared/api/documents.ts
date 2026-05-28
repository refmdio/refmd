import { client, throwIfError, withUserPopParams } from "./core";
import type { components } from "./schema";

export const documentsApi = {
  list: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/documents", {
        params: withUserPopParams({ query: { workspace_id: workspaceId } }),
      }),
    ),

  get: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}", {
        params: withUserPopParams({ path: { document_id: documentId } }),
      }),
    ),

  create: async (body: components["schemas"]["CreateDocumentRequest"]) =>
    throwIfError(
      await client.POST("/api/documents", {
        params: withUserPopParams(),
        body,
      }),
    ),

  update: async (documentId: string, body: components["schemas"]["UpdateDocumentRequest"]) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  delete: async (documentId: string) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}", {
        params: withUserPopParams({ path: { document_id: documentId } }),
      }),
    ),

  archive: async (documentId: string, body: components["schemas"]["DocumentWriteStateRequest"]) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/archive", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  unarchive: async (documentId: string, body: components["schemas"]["DocumentWriteStateRequest"]) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/unarchive", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  enableReadOnly: async (
    documentId: string,
    body: components["schemas"]["DocumentWriteStateRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/read-only/enable", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  disableReadOnly: async (
    documentId: string,
    body: components["schemas"]["DocumentWriteStateRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/read-only/disable", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  disableWritesByPolicy: async (
    documentId: string,
    body: components["schemas"]["DocumentWriteStateRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/write-disable", {
        params: withUserPopParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  reorder: async (body: components["schemas"]["ReorderDocumentRequest"]) =>
    throwIfError(
      await client.PATCH("/api/documents/reorder", {
        params: withUserPopParams(),
        body,
      }),
    ),
};
