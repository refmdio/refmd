import { createSignal, onCleanup, type Accessor } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { cryptoWorkerReady, getKekResolverSession } from "@/entities/session";
import { workspacesApi } from "@/shared/api";
import type { components } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { buildInvitationExpiryIso, buildInvitationLink } from "@/shared/lib/invite/link";

function parseOptionalPositiveInteger(raw: string, label: string): number | null {
  const value = raw.trim();
  if (!value) return null;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return parsed;
}

function parseRequiredPositiveInteger(raw: string, label: string): number {
  const parsed = parseOptionalPositiveInteger(raw, label);
  if (parsed == null) throw new Error(`${label} must be a positive integer.`);
  return parsed;
}

type GuestInvitationsListResponse = components["schemas"]["GuestInvitationsListResponse"];

interface UseGuestInvitationManagementOptions {
  workspaceId: Accessor<string | null | undefined>;
  canManageGuestInvitations: Accessor<boolean>;
  canUpdateWorkspace: Accessor<boolean>;
  guestInvitesEnabled: Accessor<boolean>;
  guestMemberLimit: Accessor<number | null | undefined>;
  setError: (value: string | null) => void;
  refetchWorkspace: () => void;
}

export function useGuestInvitationManagement(options: UseGuestInvitationManagementOptions) {
  const queryClient = useQueryClient();
  const workspaceId = () => options.workspaceId();
  const canManageGuestInvitations = () => options.canManageGuestInvitations();

  const invitations = createQuery(() => ({
    queryKey: ["guest-invitations", workspaceId()],
    queryFn: () => workspacesApi.listGuestInvitations(workspaceId()!),
    enabled: !!workspaceId() && canManageGuestInvitations(),
  }));

  const [dialogOpen, setDialogOpen] = createSignal(false);
  const [permission, setPermission] = createSignal<"view" | "edit">("view");
  const [expiryDays, setExpiryDays] = createSignal(7);
  const [maxRedemptions, setMaxRedemptions] = createSignal("1");
  const [creating, setCreating] = createSignal(false);
  const [inviteLink, setInviteLink] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);
  const [settingsEnabled, setSettingsEnabled] = createSignal(false);
  const [settingsLimit, setSettingsLimit] = createSignal("");
  const [updatingSettings, setUpdatingSettings] = createSignal(false);

  let copiedTimer: ReturnType<typeof setTimeout> | undefined;

  const invalidate = () => {
    const id = workspaceId();
    if (!id) return;
    queryClient.invalidateQueries({ queryKey: ["guest-invitations", id] });
  };

  const removeInvitationFromCache = (invitationId: string) => {
    const id = workspaceId();
    if (!id) return;

    queryClient.setQueryData<GuestInvitationsListResponse>(["guest-invitations", id], (current) => {
      if (!current) return current;
      return {
        ...current,
        invitations: current.invitations.filter(
          (invitation) => invitation.invitation_id !== invitationId,
        ),
      };
    });
  };

  const resetDialog = () => {
    setDialogOpen(false);
    setPermission("view");
    setExpiryDays(7);
    setMaxRedemptions("1");
    setInviteLink(null);
    setCopied(false);
  };

  const openDialog = () => {
    options.setError(null);
    setDialogOpen(true);
  };

  const syncSettings = () => {
    setSettingsEnabled(options.guestInvitesEnabled());
    setSettingsLimit(options.guestMemberLimit()?.toString() ?? "");
  };

  const updateSettings = async () => {
    const id = workspaceId();
    if (!id) return;

    setUpdatingSettings(true);
    options.setError(null);
    try {
      const limit = settingsLimit().trim();
      const parsedLimit = parseOptionalPositiveInteger(limit, "Guest member limit");
      await workspacesApi.update(id, {
        guest_invites_enabled: settingsEnabled(),
        guest_member_limit: parsedLimit,
      });
      options.refetchWorkspace();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to update guest settings");
    } finally {
      setUpdatingSettings(false);
    }
  };

  const createInvitation = async () => {
    const id = workspaceId();
    if (!id) return;

    setCreating(true);
    options.setError(null);
    setInviteLink(null);
    try {
      if (!cryptoWorkerReady()) throw new Error("Crypto worker not ready");

      const worker = getCryptoWorker();
      const { kekVersion } = await resolveActiveKek(id, getKekResolverSession());
      const { token: tokenBase64, tokenHash, tokenPrefix } = await worker.generateInvitationToken();
      const invitationId = crypto.randomUUID();
      const encrypted = await worker.encryptKekForInvitation({
        workspaceId: id,
        invitationId,
        token: base64UrlDecode(tokenBase64),
        keyVersion: kekVersion,
      });
      const parsedMaxRedemptions = parseRequiredPositiveInteger(
        maxRedemptions(),
        "Max redemptions",
      );

      await workspacesApi.createGuestInvitation(id, {
        invitation_id: invitationId,
        token_hash: tokenHash,
        token_prefix: tokenPrefix,
        encrypted_kek: base64UrlEncode(encrypted.encrypted),
        kek_nonce: base64UrlEncode(encrypted.nonce),
        kek_version: kekVersion,
        target_scope: "workspace",
        target_document_id: null,
        permission: permission(),
        max_redemptions: parsedMaxRedemptions,
        expires_at: buildInvitationExpiryIso(expiryDays()),
      });

      setInviteLink(buildInvitationLink(window.location.origin, tokenBase64));
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to create guest invitation");
    } finally {
      setCreating(false);
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

  const revokeInvitation = async (invitationId: string) => {
    const id = workspaceId();
    if (!id) return;
    options.setError(null);
    try {
      await workspacesApi.revokeGuestInvitation(id, invitationId);
      removeInvitationFromCache(invitationId);
      invalidate();
    } catch (err) {
      options.setError(err instanceof Error ? err.message : "Failed to revoke guest invitation");
    }
  };

  onCleanup(() => {
    if (copiedTimer) clearTimeout(copiedTimer);
  });

  return {
    invitations,
    canManageGuestInvitations,
    canUpdateWorkspace: options.canUpdateWorkspace,
    guestInvitesEnabled: options.guestInvitesEnabled,
    dialogOpen,
    openDialog,
    resetDialog,
    permission,
    setPermission,
    expiryDays,
    setExpiryDays,
    maxRedemptions,
    setMaxRedemptions,
    creating,
    inviteLink,
    copied,
    copyInviteLink,
    createInvitation,
    revokeInvitation,
    settingsEnabled,
    setSettingsEnabled,
    settingsLimit,
    setSettingsLimit,
    updatingSettings,
    updateSettings,
    syncSettings,
  };
}

export type GuestInvitationManagementModel = ReturnType<typeof useGuestInvitationManagement>;
