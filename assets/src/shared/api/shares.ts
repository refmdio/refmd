import { client, throwIfError, withUserRrpParams } from "./core";
import type { components } from "./schema";

export const sharesApi = {
  createDocumentShare: async (
    documentId: string,
    body: components["schemas"]["CreateShareRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/documents/{document_id}/shares", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
        body,
      }),
    ),

  listDocumentShares: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}/shares", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
      }),
    ),

  getDocumentShareVerificationDirectory: async (documentId: string) =>
    throwIfError(
      await client.GET("/api/documents/{document_id}/share-verification-directory", {
        params: withUserRrpParams({ path: { document_id: documentId } }),
      }),
    ),

  updateDocumentShare: async (
    documentId: string,
    shareId: string,
    body: components["schemas"]["UpdateShareRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/shares/{share_id}", {
        params: withUserRrpParams({
          path: { document_id: documentId, share_id: shareId },
        }),
        body,
      }),
    ),

  deleteDocumentShare: async (
    documentId: string,
    shareId: string,
    body: components["schemas"]["ShareManagementRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}/shares/{share_id}", {
        params: withUserRrpParams({
          path: { document_id: documentId, share_id: shareId },
        }),
        body,
      }),
    ),

  deleteDocumentShareAsAdmin: async (
    documentId: string,
    shareId: string,
    body: components["schemas"]["ShareManagementRequest"],
  ) =>
    throwIfError(
      await client.DELETE("/api/documents/{document_id}/shares/{share_id}/admin", {
        params: withUserRrpParams({ path: { document_id: documentId, share_id: shareId } }),
        body,
      }),
    ),

  updateShareExclusions: async (
    documentId: string,
    shareId: string,
    body: components["schemas"]["UpdateShareExclusionsRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/shares/{share_id}/exclusions", {
        params: withUserRrpParams({
          path: { document_id: documentId, share_id: shareId },
        }),
        body,
      }),
    ),

  updateShareKeys: async (
    documentId: string,
    shareId: string,
    body: components["schemas"]["UpdateShareKeysRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/documents/{document_id}/shares/{share_id}/keys", {
        params: withUserRrpParams({
          path: { document_id: documentId, share_id: shareId },
        }),
        body,
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
        params: withUserRrpParams({ query: { workspace_id: workspaceId } }),
      }),
    ),

  listShareLinkMounts: async (shareSlug: string) =>
    throwIfError(
      await client.GET("/api/shares/{share_slug}/mounts", {
        params: { path: { share_slug: shareSlug } },
      }),
    ),

  getShareMountMetadata: async (mountId: string) =>
    throwIfError(
      await client.GET("/api/mounts/{mount_id}", {
        params: withUserRrpParams({ path: { mount_id: mountId } }),
      }),
    ),

  getShareMountChallenge: async (mountId: string) =>
    throwIfError(
      await client.GET("/api/mounts/{mount_id}/challenge", {
        params: withUserRrpParams({ path: { mount_id: mountId } }),
      }),
    ),

  respondShareMountChallenge: async (
    mountId: string,
    body: components["schemas"]["ShareMountChallengeRequest"],
  ) =>
    throwIfError(
      await client.POST("/api/mounts/{mount_id}/challenge", {
        params: withUserRrpParams({ path: { mount_id: mountId } }),
        body,
      }),
    ),

  updateShareMount: async (
    mountId: string,
    body: components["schemas"]["UpdateShareMountRequest"],
  ) =>
    throwIfError(
      await client.PATCH("/api/mounts/{mount_id}", {
        params: withUserRrpParams({ path: { mount_id: mountId } }),
        body,
      }),
    ),

  deleteShareMount: async (mountId: string) =>
    throwIfError(
      await client.DELETE("/api/mounts/{mount_id}", {
        params: withUserRrpParams({ path: { mount_id: mountId } }),
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

  getDocumentBootstrapRequirement: async (documentToken: string) =>
    throwIfError(
      await client.GET("/api/shares/d/{document_token}", {
        params: { path: { document_token: documentToken } },
      }),
    ),

  getFolderBootstrapRequirement: async (folderToken: string) =>
    throwIfError(
      await client.GET("/api/shares/f/{folder_token}", {
        params: { path: { folder_token: folderToken } },
      }),
    ),
};
