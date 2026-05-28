import { createSignal, onCleanup, type Accessor } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import {
  authState,
  cryptoWorkerReady,
  deviceState,
  getKekResolverSession,
} from "@/entities/session";
import { ApiError, workspacesApi } from "@/shared/api";
import type { components } from "@/shared/api";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  buildGuestInvitationCreatedKeyDirectoryAppend,
  buildGuestInvitationRevokedKeyDirectoryAppend,
} from "@/shared/lib/crypto/key-directory/invitation-events";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { createWorkspacePinBootstrap } from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import { buildInvitationExpiryIso, buildInvitationLink } from "@/shared/lib/invite/link";
import {
  invitationSecretCommitment,
  invitationTokenWithFragmentSecrets,
} from "../../lib/invitation/token";

type GuestInvitationBootstrapPackage = components["schemas"]["GuestInvitationBootstrapPackage"];

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
  const [appliedGuestInvitesEnabled, setAppliedGuestInvitesEnabled] = createSignal(false);
  const [settingsLimit, setSettingsLimit] = createSignal("");
  const [settingsDirty, setSettingsDirty] = createSignal(false);
  const [updatingSettings, setUpdatingSettings] = createSignal(false);

  let copiedTimer: ReturnType<typeof setTimeout> | undefined;
  let syncedWorkspaceId: string | null | undefined;

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
    const id = workspaceId();
    if (id === syncedWorkspaceId && settingsDirty()) return;
    syncedWorkspaceId = id;
    const enabled = options.guestInvitesEnabled();
    setSettingsEnabled(enabled);
    setAppliedGuestInvitesEnabled(enabled);
    setSettingsLimit(options.guestMemberLimit()?.toString() ?? "");
    setSettingsDirty(false);
  };

  const updateSettingsEnabled = (value: boolean) => {
    setSettingsDirty(true);
    setSettingsEnabled(value);
  };

  const updateSettingsLimit = (value: string) => {
    setSettingsDirty(true);
    setSettingsLimit(value);
  };

  const updateSettings = async () => {
    const id = workspaceId();
    if (!id) return;

    setUpdatingSettings(true);
    options.setError(null);
    try {
      const limit = settingsLimit().trim();
      const parsedLimit = parseOptionalPositiveInteger(limit, "Guest member limit");
      const nextEnabled = settingsEnabled();
      const updatedWorkspace = await workspacesApi.update(id, {
        guest_invites_enabled: nextEnabled,
        ...(parsedLimit == null ? {} : { guest_member_limit: parsedLimit }),
      });
      queryClient.setQueryData(["workspace", id], updatedWorkspace);
      setAppliedGuestInvitesEnabled(nextEnabled);
      setSettingsDirty(false);
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
      const { token: lookupToken, tokenHash, tokenPrefix } = await worker.generateInvitationToken();
      const { token: clientSecret } = await worker.generateInvitationToken();
      const bootstrapSecretCommitment = await invitationSecretCommitment(
        lookupToken,
        clientSecret,
        "guest",
      );
      const invitationId = crypto.randomUUID();
      const parsedMaxRedemptions = parseRequiredPositiveInteger(
        maxRedemptions(),
        "Max redemptions",
      );
      const auth = authState();
      const device = deviceState();
      if (!auth?.user.id || !device?.deviceId) throw new Error("Session not ready");
      const redeemAuthority = await worker.generateInvitationRedeemAuthority({ invitationId });
      const keyVersionContext = {
        workspace_kek_version: kekVersion,
        share_key_version: "NOT_APPLICABLE",
        dek_version: "NOT_APPLICABLE",
      };
      const capabilityContext = {
        guest_invitation_id: invitationId,
        permission: permission(),
        scope_id: "none",
        scope_kind: "workspace",
        workspace_id: id,
      };
      const expiresAt = buildInvitationExpiryIso(expiryDays());
      const expiresEventSequence = Math.floor(Date.parse(expiresAt) / 1000);
      const createBodyBase = {
        invitation_id: invitationId,
        token_hash: tokenHash,
        token_prefix: tokenPrefix,
        kek_version: kekVersion,
        scope_kind: "workspace" as const,
        permission: permission(),
        bootstrap_key_commitment: bootstrapSecretCommitment,
        max_redemptions: parsedMaxRedemptions,
        expires_at: expiresAt,
      };
      const buildCreateAttempt = async () => {
        const directory = await fetchVerifiedKeyDirectory({
          scopeKind: "workspace",
          scopeId: id,
          popDeviceId: device.deviceId,
        });
        const workspacePinBootstrap = await createWorkspacePinBootstrap({
          workspaceId: id,
          checkpointEnvelope: directory.checkpoint,
          actorUserId: auth.user.id,
          actorDeviceId: device.deviceId,
        });
        const bootstrapPackage = await worker.wrapKekForInvitationBootstrap({
          protocol: "refmd.guest-invitation-bootstrap",
          workspaceId: id,
          keyVersion: kekVersion,
          bootstrapSecret: clientSecret,
          aad: {
            protocol: "refmd.guest-invitation-bootstrap",
            version: 1,
            suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
            workspace_id: id,
            guest_invitation_id: invitationId,
            scope_kind: "workspace",
            scope_id: "none",
            permission: permission(),
            key_version_context: keyVersionContext,
            token_hash: tokenHash,
          },
          plaintext: {
            protocol: "refmd.guest-invitation-bootstrap",
            version: 1,
            workspace_id: id,
            guest_invitation_id: invitationId,
            scope_kind: "workspace",
            scope_id: "none",
            permission: permission(),
            key_version_context: keyVersionContext,
            workspace_key_directory_checkpoint: directory.checkpoint,
            workspace_pin_bootstrap_hash: workspacePinBootstrap.hash,
            workspace_pin_bootstrap: workspacePinBootstrap.bootstrap,
          },
          redeemAuthorityInvitationId: invitationId,
        });
        const keyDirectoryAppend = await buildGuestInvitationCreatedKeyDirectoryAppend({
          workspaceId: id,
          actorUserId: auth.user.id,
          actorDeviceId: device.deviceId,
          checkpointEnvelope: directory.checkpoint,
          invitationId,
          scopeKind: "workspace",
          scopeId: "none",
          permission: permission(),
          kekVersion,
          expiresEventSequence,
          redeemAuthority: {
            signingKeyId: redeemAuthority.signer.signing_key_id,
            hybridSigningPublicKeyMaterial: redeemAuthority.hybridSigningPublicKeyMaterial,
          },
          bootstrapKeyCommitment: bootstrapSecretCommitment,
          bootstrapPackageHash: blake3Base64Url(
            canonicalizeStrictBytes(bootstrapPackage as StrictJsonValue),
          ),
          bootstrapSuiteId: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
          capabilityContextHash: blake3Base64Url(
            canonicalizeStrictBytes(capabilityContext as StrictJsonValue),
          ),
        });
        return {
          previousCheckpoint: directory.checkpoint,
          body: {
            ...createBodyBase,
            encrypted_bootstrap_package: bootstrapPackage as GuestInvitationBootstrapPackage,
            bootstrap_package_hash: blake3Base64Url(
              canonicalizeStrictBytes(bootstrapPackage as StrictJsonValue),
            ),
            bootstrap_package_key_recipient_wrap:
              bootstrapPackage.package_key_recipient_wrap as components["schemas"]["InvitationBootstrapCiphertext"],
            bootstrap_package_key_maintenance_wrap:
              bootstrapPackage.package_key_maintenance_wrap as components["schemas"]["InvitationBootstrapMaintenanceWrap"],
            bootstrap_suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305" as const,
            capability_context_hash: blake3Base64Url(
              canonicalizeStrictBytes(capabilityContext as StrictJsonValue),
            ),
            workspace_key_directory_events: keyDirectoryAppend.events,
            workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
          },
          append: keyDirectoryAppend,
        };
      };
      let { previousCheckpoint, body, append: keyDirectoryAppend } = await buildCreateAttempt();
      try {
        await workspacesApi.createGuestInvitation(id, body);
      } catch (err) {
        if (
          !(err instanceof ApiError && err.status === 422 && err.code === "invalid_key_directory")
        ) {
          throw err;
        }
        ({ previousCheckpoint, body, append: keyDirectoryAppend } = await buildCreateAttempt());
        await workspacesApi.createGuestInvitation(id, body);
      }
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: id,
        checkpointEnvelope: keyDirectoryAppend.checkpoint,
        checkpointAncestry: [previousCheckpoint],
        eventAncestry: keyDirectoryAppend.events,
      });

      setInviteLink(
        buildInvitationLink(
          window.location.origin,
          invitationTokenWithFragmentSecrets(lookupToken, clientSecret),
        ),
      );
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
      if (!cryptoWorkerReady()) throw new Error("Crypto worker not ready");

      const auth = authState();
      const device = deviceState();
      if (!auth?.user.id || !device?.deviceId) throw new Error("Session not ready");
      const buildAppend = async () => {
        const directory = await fetchVerifiedKeyDirectory({
          scopeKind: "workspace",
          scopeId: id,
          popDeviceId: device.deviceId,
        });
        return {
          previousCheckpoint: directory.checkpoint,
          append: await buildGuestInvitationRevokedKeyDirectoryAppend({
            workspaceId: id,
            actorUserId: auth.user.id,
            actorDeviceId: device.deviceId,
            checkpointEnvelope: directory.checkpoint,
            invitationId,
          }),
        };
      };
      let { previousCheckpoint, append: keyDirectoryAppend } = await buildAppend();
      try {
        await workspacesApi.revokeGuestInvitation(id, invitationId, {
          workspace_key_directory_events: keyDirectoryAppend.events,
          workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
        });
      } catch (err) {
        if (
          !(err instanceof ApiError && err.status === 422 && err.code === "invalid_key_directory")
        ) {
          throw err;
        }
        ({ previousCheckpoint, append: keyDirectoryAppend } = await buildAppend());
        await workspacesApi.revokeGuestInvitation(id, invitationId, {
          workspace_key_directory_events: keyDirectoryAppend.events,
          workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
        });
      }
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: id,
        checkpointEnvelope: keyDirectoryAppend.checkpoint,
        checkpointAncestry: [previousCheckpoint],
        eventAncestry: keyDirectoryAppend.events,
      });
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
    guestInvitesEnabled: appliedGuestInvitesEnabled,
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
    setSettingsEnabled: updateSettingsEnabled,
    settingsLimit,
    setSettingsLimit: updateSettingsLimit,
    updatingSettings,
    updateSettings,
    syncSettings,
  };
}

export type GuestInvitationManagementModel = ReturnType<typeof useGuestInvitationManagement>;
