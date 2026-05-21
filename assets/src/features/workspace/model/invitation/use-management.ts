import { createSignal, onCleanup, type Accessor } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { type components, workspacesApi } from "@/shared/api";
import {
  authState,
  cryptoWorkerReady,
  deviceState,
  getKekResolverSession,
} from "@/entities/session";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import {
  buildWorkspaceInvitationCreatedKeyDirectoryAppend,
  buildWorkspaceInvitationRevokedKeyDirectoryAppend,
} from "@/shared/lib/crypto/key-directory/invitation-events";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { createWorkspacePinBootstrap } from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import { buildInvitationExpiryIso, buildInvitationLink } from "@/shared/lib/invite/link";
import {
  invitationSecretCommitment,
  invitationTokenWithFragmentSecrets,
} from "../../lib/invitation/token";

export interface WorkspaceInvitationRoleOption {
  id: string;
  name: string;
  base_role: string;
  is_default?: boolean;
}

type WorkspaceInvitationBootstrapPackage =
  components["schemas"]["WorkspaceInvitationBootstrapPackage"];

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
      const { token: bootstrapSecret } = await worker.generateInvitationToken();

      const invitationId = crypto.randomUUID();
      const expiresAt = buildInvitationExpiryIso(expiryDays());
      const expiresEventSequence = Math.floor(Date.parse(expiresAt) / 1000);
      const auth = authState();
      const device = deviceState();
      if (!auth?.user.id || !device?.deviceId) throw new Error("Session not ready");
      const directory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: id,
        popDeviceId: device.deviceId,
      });
      const roleId = selectedRoleId();
      const selectedRole = roleId ? assignableRoles().find((role) => role.id === roleId) : null;
      const fallbackRole =
        assignableRoles().find((role) => role.is_default) ?? assignableRoles()[0];
      const targetRole = selectedRole ?? fallbackRole;
      if (!targetRole) throw new Error("No assignable role available.");
      const bootstrapSecretCommitment = await invitationSecretCommitment(
        tokenBase64,
        bootstrapSecret,
        "workspace",
      );
      const redeemAuthority = await worker.generateInvitationRedeemAuthority({ invitationId });
      const workspacePinBootstrap = await createWorkspacePinBootstrap({
        workspaceId: id,
        checkpointEnvelope: directory.checkpoint,
        actorUserId: auth.user.id,
        actorDeviceId: device.deviceId,
      });
      const capabilityContext = {
        invited_email: email.trim().toLowerCase(),
        invitation_id: invitationId,
        role_id: targetRole.id,
        workspace_id: id,
      };
      const bootstrapPackage = await worker.wrapKekForInvitationBootstrap({
        protocol: "refmd.workspace-invitation-bootstrap",
        workspaceId: id,
        keyVersion: currentKekVersion,
        bootstrapSecret,
        aad: {
          protocol: "refmd.workspace-invitation-bootstrap",
          version: 1,
          suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
          workspace_id: id,
          invitation_id: invitationId,
          role_id: targetRole.id,
          invited_email: email.trim().toLowerCase(),
          key_version_context: { workspace_kek_version: currentKekVersion },
          token_hash: tokenHash,
        },
        plaintext: {
          protocol: "refmd.workspace-invitation-bootstrap",
          version: 1,
          workspace_id: id,
          invitation_id: invitationId,
          role_id: targetRole.id,
          invited_email: email.trim().toLowerCase(),
          kek_version: currentKekVersion,
          workspace_key_directory_checkpoint: directory.checkpoint,
          workspace_pin_bootstrap_hash: workspacePinBootstrap.hash,
          workspace_pin_bootstrap: workspacePinBootstrap.bootstrap,
        },
        redeemAuthorityInvitationId: invitationId,
      });
      const keyDirectoryAppend = await buildWorkspaceInvitationCreatedKeyDirectoryAppend({
        workspaceId: id,
        actorUserId: auth.user.id,
        actorDeviceId: device.deviceId,
        checkpointEnvelope: directory.checkpoint,
        invitationId,
        roleId: targetRole.id,
        baseRole: targetRole.base_role,
        kekVersion: currentKekVersion,
        invitedEmail: email,
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

      await workspacesApi.createInvitation(id, {
        invitation_id: invitationId,
        token_hash: tokenHash,
        token_prefix: tokenPrefix,
        kek_version: currentKekVersion,
        role_id: targetRole.id,
        invited_email: email,
        expires_at: expiresAt,
        encrypted_bootstrap_package: bootstrapPackage as WorkspaceInvitationBootstrapPackage,
        bootstrap_key_commitment: bootstrapSecretCommitment,
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
      });
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: id,
        checkpointEnvelope: keyDirectoryAppend.checkpoint,
        checkpointAncestry: [directory.checkpoint],
        eventAncestry: keyDirectoryAppend.events,
      });

      setInviteLink(
        buildInvitationLink(
          window.location.origin,
          invitationTokenWithFragmentSecrets(tokenBase64, bootstrapSecret),
        ),
      );
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
      if (!cryptoWorkerReady()) throw new Error("Crypto worker not ready");

      const auth = authState();
      const device = deviceState();
      if (!auth?.user.id || !device?.deviceId) throw new Error("Session not ready");
      const directory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: id,
        popDeviceId: device.deviceId,
      });
      const keyDirectoryAppend = await buildWorkspaceInvitationRevokedKeyDirectoryAppend({
        workspaceId: id,
        actorUserId: auth.user.id,
        actorDeviceId: device.deviceId,
        checkpointEnvelope: directory.checkpoint,
        invitationId,
      });
      await workspacesApi.revokeInvitation(id, invitationId, {
        workspace_key_directory_events: keyDirectoryAppend.events,
        workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
      });
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: id,
        checkpointEnvelope: keyDirectoryAppend.checkpoint,
        checkpointAncestry: [directory.checkpoint],
        eventAncestry: keyDirectoryAppend.events,
      });
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
