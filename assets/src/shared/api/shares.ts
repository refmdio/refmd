import { client, throwIfError } from "./core";
import type { components } from "./schema";

export const sharesApi = {
  createDocumentShare: async (
    documentId: string,
    body: components["schemas"]["CreateShareRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/shares", {
        params: { path: { document_id: documentId } },
        body,
      }),
    ),

  listDocumentShares: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}/shares", {
        params: { path: { document_id: documentId } },
      }),
    ),

  getDocumentShareVerificationDirectory: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}/share-verification-directory", {
        params: { path: { document_id: documentId } },
      }),
    ),

  updateDocumentShare: async (
    documentId: string,
    shareId: string,
    manageToken: string,
    body: components["schemas"]["UpdateShareRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/shares/{share_id}", {
        params: {
          path: { document_id: documentId, share_id: shareId },
          header: { authorization: manageToken },
        },
        headers: { Authorization: manageToken },
        body,
      }),
    ),

  deleteDocumentShare: async (
    documentId: string,
    shareId: string,
    opts?: { manageToken?: string },
  ) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}/shares/{share_id}", {
        params: {
          path: { document_id: documentId, share_id: shareId },
          ...(opts?.manageToken ? { header: { authorization: opts.manageToken } } : {}),
        },
        ...(opts?.manageToken ? { headers: { Authorization: opts.manageToken } } : {}),
      }),
    ),

  deleteDocumentShareAsAdmin: async (documentId: string, shareId: string) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}/shares/{share_id}/admin", {
        params: { path: { document_id: documentId, share_id: shareId } },
      }),
    ),

  updateShareExclusions: async (
    documentId: string,
    shareId: string,
    manageToken: string,
    body: components["schemas"]["UpdateShareExclusionsRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/shares/{share_id}/exclusions", {
        params: {
          path: { document_id: documentId, share_id: shareId },
          header: { authorization: manageToken },
        },
        headers: { Authorization: manageToken },
        body,
      }),
    ),

  updateShareKeys: async (
    documentId: string,
    shareId: string,
    manageToken: string,
    body: components["schemas"]["UpdateShareKeysRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/shares/{share_id}/keys", {
        params: {
          path: { document_id: documentId, share_id: shareId },
          header: { authorization: manageToken },
        },
        headers: { Authorization: manageToken },
        body,
      }),
    ),

  listShareMountsForShare: async (shareSlug: string) =>
    throwIfError(
      await client.GET("/api/shares/{share_slug}/mounts", {
        params: { path: { share_slug: shareSlug } },
      }),
    ),

  createShareMount: async (body: components["schemas"]["CreateShareMountRequest"]) =>
    throwIfError(
      await client.POST("/api/mounts", {
        body,
      }),
    ),

  listShareMounts: async (workspaceId: string) =>
    throwIfError(
      await client.GET("/api/mounts", {
        params: { query: { workspace_id: workspaceId } },
      }),
    ),

  getShareMount: async (
    mountId: string,
    options?: { documentId?: string | null; shareId?: string | null },
  ) =>
    throwIfError(
      await client.GET("/api/mounts/{mount_id}", {
        params: {
          path: { mount_id: mountId },
          ...(options?.shareId
            ? { query: { share: options.shareId } }
            : options?.documentId
              ? { query: { document_id: options.documentId } }
              : {}),
        },
      }),
    ),

  getShareMountFolder: async (mountId: string, folderToken: string) =>
    throwIfError(
      await client.GET("/api/mounts/{mount_id}/folders/{folder_token}", {
        params: { path: { mount_id: mountId, folder_token: folderToken } },
      }),
    ),

  getShareMountChallenge: async (mountId: string) =>
    throwIfError(
      await client.GET("/api/mounts/{mount_id}/challenge", {
        params: { path: { mount_id: mountId } },
      }),
    ),

  respondShareMountChallenge: async (
    mountId: string,
    body: components["schemas"]["ShareMountChallengeRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/mounts/{mount_id}/challenge", {
        params: { path: { mount_id: mountId } },
        body,
      }),
    ),

  updateShareMount: async (
    mountId: string,
    body: components["schemas"]["UpdateShareMountRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/mounts/{mount_id}", {
        params: { path: { mount_id: mountId } },
        body,
      }),
    ),

  deleteShareMount: async (mountId: string) =>
    throwIfError(
      await client.DELETE("/api/mounts/{mount_id}", {
        params: { path: { mount_id: mountId } },
      }),
    ),

  getLanding: async (shareSlug: string) =>
    throwIfError(
      await client.GET("/api/shares/{share_slug}", {
        params: { path: { share_slug: shareSlug } },
      }),
    ),

  bootstrap: async (shareSlug: string, body: components["schemas"]["ShareBootstrapRequest"]) =>
    throwIfError(
      await client.POST("/api/shares/{share_slug}/bootstrap", {
        params: { path: { share_slug: shareSlug } },
        body,
      }),
    ),

  getChallenge: async (shareSlug: string) =>
    throwIfError(
      await client.GET("/api/shares/{share_slug}/challenge", {
        params: { path: { share_slug: shareSlug } },
      }),
    ),

  respondChallenge: async (
    shareSlug: string,
    body: components["schemas"]["SharePasswordChallengeRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/shares/{share_slug}/challenge", {
        params: { path: { share_slug: shareSlug } },
        body,
      }),
    ),

  getDocumentBootstrap: async (documentToken: string) =>
    throwIfError(
      await client.GET("/api/shares/d/{document_token}", {
        params: { path: { document_token: documentToken } },
      }),
    ),

  getFolderBootstrap: async (folderToken: string) =>
    throwIfError(
      await client.GET("/api/shares/f/{folder_token}", {
        params: { path: { folder_token: folderToken } },
      }),
    ),
};
