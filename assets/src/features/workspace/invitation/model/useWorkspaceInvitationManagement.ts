import { createSignal, onCleanup, type Accessor } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { type components, workspacesApi } from "@/shared/api";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { buildInvitationExpiryIso, buildInvitationLink } from "../lib/invitation-utils";

export interface WorkspaceInvitationRoleOption {
  id: string;
  name: string;
  base_role: string;
}

interface UseWorkspaceInvitationManagementOptions {
  workspaceId: Accessor<string | null | undefined>;
  canManageInvitations: Accessor<boolean>;
  assignableRoles: Accessor<WorkspaceInvitationRoleOption[]>;
  defaultRoleAssignable: Accessor<boolean>;
  setError: (value: string | null) => void;
}

type InvitationListItem = components["schemas"]["InvitationListItem"];

export function useWorkspaceInvitationManagement(options: UseWorkspaceInvitationManagementOptions) {
  const queryClient = useQueryClient();
  const workspaceId = () => options.workspaceId();
  const canManageInvitations = () => options.canManageInvitations();
  const assignableRoles = () => options.assignableRoles();
  const defaultRoleAssignable = () => options.defaultRoleAssignable();

  const invitations = createQuery(() => ({
    queryKey: ["workspace-invitations", workspaceId()],
    queryFn: () => workspacesApi.listInvitations(workspaceId()!),
    enabled: !!workspaceId() && canManageInvitations(),
  }));

  const [inviteDialogOpen, setInviteDialogOpen] = createSignal(false);
  const [inviteEmail, setInviteEmail] = createSignal("");
  const [selectedRoleId, setSelectedRoleId] = createSignal("");
  const [expiryDays, setExpiryDays] = createSignal(7);
  const [isInviting, setIsInviting] = createSignal(false);
  const [inviteLink, setInviteLink] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);

  let copiedTimer: ReturnType<typeof setTimeout> | undefined;

  const invalidateInvitations = () => {
    const id = workspaceId();
    if (!id) return;
    queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });
  };

  const resetInviteState = () => {
    setInviteDialogOpen(false);
    setInviteEmail("");
    setSelectedRoleId("");
    setExpiryDays(7);
    setInviteLink(null);
    setCopied(false);
    if (copiedTimer) {
      clearTimeout(copiedTimer);
      copiedTimer = undefined;
    }
  };

  const openInviteDialog = () => {
    options.setError(null);
    setInviteDialogOpen(true);
  };

  const createInvitation = async () => {
    const email = inviteEmail().trim();
    const id = workspaceId();
    if (!email || !id) return;

    setIsInviting(true);
    options.setError(null);
    setInviteLink(null);
    try {
      if (!cryptoWorkerReady()) throw new Error("Crypto worker not ready");

      const worker = getCryptoWorker();
      const { kekVersion: currentKekVersion } = await resolveActiveKek(id, getKekResolverSession());
      const { token: tokenBase64, tokenHash, tokenPrefix } = await worker.generateInvitationToken();

      const invitationId = crypto.randomUUID();
      const encrypted = await worker.encryptKekForInvitation({
        workspaceId: id,
        invitationId,
        token: base64UrlDecode(tokenBase64),
        keyVersion: currentKekVersion,
      });

      const expiresAt = buildInvitationExpiryIso(expiryDays());

      await workspacesApi.createInvitation(id, {
        invitation_id: invitationId,
        token_hash: tokenHash,
        token_prefix: tokenPrefix,
        encrypted_kek: base64UrlEncode(encrypted.encrypted),
        kek_nonce: base64UrlEncode(encrypted.nonce),
        kek_version: currentKekVersion,
        role_id: selectedRoleId() || null,
        invited_email: email,
        expires_at: expiresAt,
      });

      setInviteLink(buildInvitationLink(window.location.origin, tokenBase64));
      invalidateInvitations();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to create invitation");
    } finally {
      setIsInviting(false);
    }
  };

  const copyInviteLink = async () => {
    const link = inviteLink();
    if (!link) return;

    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
      if (copiedTimer) clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => {
        setCopied(false);
        copiedTimer = undefined;
      }, 2000);
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to copy invitation link");
    }
  };

  const revokeInvitation = async (invitationId: InvitationListItem["invitation_id"]) => {
    const id = workspaceId();
    if (!id) return;

    options.setError(null);
    try {
      await workspacesApi.revokeInvitation(id, invitationId);
      invalidateInvitations();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to revoke invitation");
    }
  };

  const hasPendingInvitations = () => {
    if (!canManageInvitations()) return false;
    return (invitations.data?.invitations?.length ?? 0) > 0;
  };

  onCleanup(() => {
    if (copiedTimer) clearTimeout(copiedTimer);
  });

  return {
    invitations,
    inviteDialogOpen,
    openInviteDialog,
    resetInviteState,
    inviteEmail,
    setInviteEmail,
    selectedRoleId,
    setSelectedRoleId,
    expiryDays,
    setExpiryDays,
    isInviting,
    inviteLink,
    copied,
    copyInviteLink,
    createInvitation,
    revokeInvitation,
    assignableRoles,
    defaultRoleAssignable,
    canManageInvitations,
    hasPendingInvitations,
  };
}

export type WorkspaceInvitationManagementModel = ReturnType<
  typeof useWorkspaceInvitationManagement
>;
