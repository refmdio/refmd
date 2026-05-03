import { client, throwIfError } from "./core";
import type { components } from "./schema";

export const publicApi = {
  getAuthor: async (authorSlug: string) =>
    throwIfError(
      await client.GET("/api/public/authors/{author_slug}", {
        params: { path: { author_slug: authorSlug } },
      }),
    ),

  getDocument: async (authorSlug: string, documentSlug: string) =>
    throwIfError(
      await client.GET("/api/public/authors/{author_slug}/documents/{document_slug}", {
        params: { path: { author_slug: authorSlug, document_slug: documentSlug } },
      }),
    ),

  publishDocument: async (
    documentId: string,
    body: components["schemas"]["CreatePublicationRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/publication", {
        params: { path: { document_id: documentId } },
        body,
      }),
    ),

  getPublication: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}/publication", {
        params: { path: { document_id: documentId } },
      }),
    ),

  updatePublication: async (
    documentId: string,
    body: components["schemas"]["UpdatePublicationRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/publication", {
        params: { path: { document_id: documentId } },
        body,
      }),
    ),

  unpublishDocument: async (documentId: string) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}/publication", {
        params: { path: { document_id: documentId } },
      }),
    ),

  syncPublicationContent: async (
    documentId: string,
    body: components["schemas"]["UpdatePublicationContentRequest"],
  ) =>
    throwIfError(
      await client.PUT("/api/documents/{document_id}/publication/content", {
        params: { path: { document_id: documentId } },
        body,
      }),
    ),
};
