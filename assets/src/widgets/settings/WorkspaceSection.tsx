import { createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldLabel, FieldDescription } from "@/shared/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";
import {
  UserPlusIcon,
  UserMinusIcon,
  ShieldIcon,
  MailIcon,
  TrashIcon,
  CopyIcon,
  CheckIcon,
  PlusIcon,
  PencilIcon,
  StarIcon,
} from "lucide-solid";
import { workspacesApi, encryptionApi, ApiError } from "@/shared/api";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import { performKekRotation } from "@/features/devices";
import { authState, deviceState } from "@/shared/lib/auth-state";
import {
  currentWorkspaceId,
  setCurrentWorkspaceId,
  ALL_PERMISSIONS,
  PERMISSION_LABELS,
  PRIVILEGE_LEVEL,
  CEILING,
  isAtOrAbove,
  defaultGrant,
  checkEffectivePermission,
} from "@/entities/workspace";
import type { BaseRole, Permission } from "@/entities/workspace";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  randomBytes,
  base64UrlEncode,
  base64UrlDecode,
  encryptKekForInvitation,
  decryptKekFromDeviceEnvelope,
  decryptKekFromMemberEnvelope,
  encryptKekForDevice,
  wrapKekWithUmk,
  unwrapKekFromBackup,
  verifyTofu,
  handleTofuResult,
} from "@/shared/lib/crypto";

interface PermissionOverride {
  permission: string;
  granted: boolean;
}

export function WorkspaceSection() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const wsId = () => currentWorkspaceId();

  // ─── Queries ─────────────────────────────────────────────────
  const workspace = createQuery(() => ({
    queryKey: ["workspace", wsId()],
    queryFn: () => workspacesApi.get(wsId()!),
    enabled: !!wsId(),
  }));

  const members = createQuery(() => ({
    queryKey: ["workspace-members", wsId()],
    queryFn: () => workspacesApi.listMembers(wsId()!),
    enabled: !!wsId(),
  }));

  const roles = createQuery(() => ({
    queryKey: ["workspace-roles", wsId()],
    queryFn: () => workspacesApi.listRoles(wsId()!),
    enabled: !!wsId(),
  }));

  // ─── Common state ────────────────────────────────────────────
  const [error, setError] = createSignal<string | null>(null);
  const [info, setInfo] = createSignal<string | null>(null);
  const currentUserId = () => authState()?.user.id;
  const currentMember = () => {
    const fromList = members.data?.members?.find((m) => m.user_id === currentUserId());
    if (fromList) return fromList;
    const ws = workspace.data;
    if (ws?.current_user_role_id) {
      return {
        role_id: ws.current_user_role_id,
        base_role: ws.current_user_base_role ?? "",
        user_id: currentUserId() ?? "",
      };
    }
    return undefined;
  };
  const isOwner = () => currentMember()?.base_role === "owner";
  const memberPermissionDenied = () =>
    members.error instanceof ApiError && members.error.status === 403;

  const hasPermission = (permission: string) => {
    const member = currentMember();
    const roleList = roles.data?.roles;
    if (!member || !roleList) return false;
    return checkEffectivePermission(roleList, member.role_id, permission);
  };

  const canUpdateWorkspace = () => hasPermission("workspace:update");
  const canInvite = () => hasPermission("member:invite");
  const canChangeRole = () => hasPermission("member:change_role");
  const canRemoveMember = () => hasPermission("member:remove");
  const canManageRoles = () => hasPermission("role:manage");

  const assignableRoles = () => {
    const member = currentMember();
    const roleList = roles.data?.roles;
    if (!member || !roleList) return [];
    const actorPower = PRIVILEGE_LEVEL[member.base_role as BaseRole] ?? 0;
    const actorPerms = new Set(
      ALL_PERMISSIONS.filter((p) => checkEffectivePermission(roleList, member.role_id, p)),
    );
    return roleList.filter((r: any) => {
      if (PRIVILEGE_LEVEL[r.base_role as BaseRole] > actorPower) return false;
      return ALL_PERMISSIONS.every((p) => {
        if (!checkEffectivePermission(roleList, r.id, p)) return true;
        return actorPerms.has(p);
      });
    });
  };

  const defaultRoleAssignable = () => {
    const roleList = roles.data?.roles;
    if (!roleList) return true;
    const dr = roleList.find((r: any) => r.is_default);
    if (!dr) return true;
    return assignableRoles().some((r: any) => r.id === dr.id);
  };

  const invitations = createQuery(() => ({
    queryKey: ["workspace-invitations", wsId()],
    queryFn: () => workspacesApi.listInvitations(wsId()!),
    enabled: !!wsId() && canInvite(),
  }));

  const refetchAll = () => {
    const id = wsId();
    queryClient.invalidateQueries({ queryKey: ["workspace", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-members", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });
    queryClient.invalidateQueries({ queryKey: ["workspaces"] });
  };

  // ─── Workspace info edit ─────────────────────────────────────
  const [editingName, setEditingName] = createSignal(false);
  const [newName, setNewName] = createSignal("");
  const [editingDescription, setEditingDescription] = createSignal(false);
  const [newDescription, setNewDescription] = createSignal("");
  const [editingSlug, setEditingSlug] = createSignal(false);
  const [newSlug, setNewSlug] = createSignal("");
  const [updating, setUpdating] = createSignal(false);

  const handleUpdateName = async () => {
    const name = newName().trim();
    const id = wsId();
    if (!name || !id) return;
    setUpdating(true);
    setError(null);
    try {
      await workspacesApi.update(id, { name });
      refetchAll();
      setEditingName(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setUpdating(false);
    }
  };

  const handleUpdateDescription = async () => {
    const description = newDescription().trim() || null;
    const id = wsId();
    if (!id) return;
    setUpdating(true);
    setError(null);
    try {
      await workspacesApi.update(id, { description });
      refetchAll();
      setEditingDescription(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setUpdating(false);
    }
  };

  const handleUpdateSlug = async () => {
    const slug = newSlug().trim();
    const id = wsId();
    if (!slug || !id) return;
    setUpdating(true);
    setError(null);
    try {
      await workspacesApi.update(id, { slug });
      refetchAll();
      setEditingSlug(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update");
    } finally {
      setUpdating(false);
    }
  };

  // ─── Delete workspace ────────────────────────────────────────
  const [showDelete, setShowDelete] = createSignal(false);
  const [deleting, setDeleting] = createSignal(false);

  const handleDelete = async () => {
    const id = wsId();
    if (!id) return;
    setDeleting(true);
    try {
      await workspacesApi.delete(id);
      setCurrentWorkspaceId(null);
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      setShowDelete(false);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete");
    } finally {
      setDeleting(false);
    }
  };

  // ─── Leave workspace ─────────────────────────────────────────
  const [showLeave, setShowLeave] = createSignal(false);
  const [leaving, setLeaving] = createSignal(false);

  const handleLeave = async () => {
    const id = wsId();
    const userId = currentUserId();
    if (!id || !userId) return;
    setLeaving(true);
    try {
      await workspacesApi.removeMember(id, userId);
      setCurrentWorkspaceId(null);
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      setShowLeave(false);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to leave");
    } finally {
      setLeaving(false);
    }
  };

  // ─── Remove member ───────────────────────────────────────────
  const [removeTarget, setRemoveTarget] = createSignal<{
    user_id: string;
    name: string;
  } | null>(null);
  const [removing, setRemoving] = createSignal(false);

  const triggerKekRotation = async (rotationList: WorkspaceRotationInfo[]) => {
    if (rotationList.length === 0) return;
    const auth = authState();
    const device = deviceState();
    if (!auth || !auth.umk || !auth.identityKeys || !device?.deviceEcdhPrivate) return;
    await performKekRotation(
      rotationList,
      {
        user: auth.user,
        umk: auth.umk,
        identityKeys: auth.identityKeys,
      },
      {
        deviceId: device.deviceId,
        deviceEcdhPrivate: device.deviceEcdhPrivate,
      },
    );
  };

  const handleRemoveMember = async () => {
    const target = removeTarget();
    const id = wsId();
    if (!target || !id) return;
    setRemoving(true);
    setError(null);
    try {
      const res = await workspacesApi.removeMember(id, target.user_id);
      setRemoveTarget(null);

      const isSelfRemoval = target.user_id === currentUserId();
      if (isSelfRemoval) {
        setCurrentWorkspaceId(null);
        queryClient.invalidateQueries({ queryKey: ["workspaces"] });
        navigate("/dashboard");
        return;
      }

      refetchAll();
      const rotationList = (res as any)?.workspaces_needing_kek_rotation ?? [];
      if (rotationList.length > 0) {
        try {
          await triggerKekRotation(rotationList);
          refetchAll();
        } catch {
          setInfo("Member removed. KEK rotation could not complete automatically.");
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove member");
    } finally {
      setRemoving(false);
    }
  };

  // ─── Change role ─────────────────────────────────────────────
  const [roleChangeTarget, setRoleChangeTarget] = createSignal<{
    user_id: string;
    name: string;
    current_role_id: string;
  } | null>(null);
  const [selectedRoleId, setSelectedRoleId] = createSignal("");
  const [changingRole, setChangingRole] = createSignal(false);

  const handleChangeRole = async () => {
    const target = roleChangeTarget();
    const roleId = selectedRoleId();
    const id = wsId();
    if (!target || !roleId || !id) return;
    setChangingRole(true);
    setError(null);
    try {
      await workspacesApi.changeMemberRole(id, target.user_id, roleId);
      setRoleChangeTarget(null);
      refetchAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change role");
    } finally {
      setChangingRole(false);
    }
  };

  // ─── Invite ──────────────────────────────────────────────────
  const [showInvite, setShowInvite] = createSignal(false);
  const [inviteEmail, setInviteEmail] = createSignal("");
  const [inviteRoleId, setInviteRoleId] = createSignal("");
  const [inviteExpiryDays, setInviteExpiryDays] = createSignal(7);
  const [inviting, setInviting] = createSignal(false);
  const [inviteLink, setInviteLink] = createSignal<string | null>(null);
  const [copied, setCopied] = createSignal(false);

  const handleInvite = async () => {
    const email = inviteEmail().trim();
    const id = wsId();
    if (!email || !id) return;

    setInviting(true);
    setError(null);
    setInviteLink(null);
    try {
      const auth = authState();
      const device = deviceState();
      if (!auth || !device) throw new Error("Not authenticated");

      const deviceId = device.deviceId;

      type KeysResponse = Awaited<ReturnType<typeof encryptionApi.getWorkspaceKeysWithPop>>;
      let keys: KeysResponse["keys"] = [];
      let current_kek_version = 0;
      try {
        const keysResponse = await encryptionApi.getWorkspaceKeysWithPop(id, deviceId);
        keys = keysResponse.keys;
        current_kek_version = keysResponse.current_kek_version;
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) {
          const details = (e.body as Record<string, unknown>)?.details as
            | Record<string, unknown>
            | undefined;
          current_kek_version = (details?.current_kek_version as number) ?? 0;
        } else {
          throw e;
        }
      }
      if (current_kek_version === 0) {
        throw new Error("Encryption not set up for this workspace");
      }

      if (!device.deviceEcdhPrivate) {
        throw new Error("Device ECDH private key not available");
      }

      const activeKey = keys.find((k) => k.key_version === current_kek_version);

      let kek: Uint8Array;

      if (activeKey && activeKey.sender_ecdh_public_key && activeKey.sender_signing_public_key) {
        const senderSigningPk = base64UrlDecode(activeKey.sender_signing_public_key);
        const senderEcdhPk = base64UrlDecode(activeKey.sender_ecdh_public_key);

        const tofuResult = await verifyTofu(
          auth.user.id,
          activeKey.sender_device_id,
          senderSigningPk,
          senderEcdhPk,
        );
        if (
          tofuResult.status === "identity_key_changed" ||
          tofuResult.status === "ecdh_key_mismatch"
        ) {
          throw new Error("Key verification failed for KEK sender device.");
        }
        await handleTofuResult(tofuResult);

        kek = decryptKekFromDeviceEnvelope(
          base64UrlDecode(activeKey.encrypted_kek),
          base64UrlDecode(activeKey.nonce),
          device.deviceEcdhPrivate,
          senderEcdhPk,
          id,
          auth.user.id,
          activeKey.sender_device_id,
          deviceId,
          current_kek_version,
        );

        if (auth.umk) {
          const kekRef = kek;
          (async () => {
            try {
              await encryptionApi.getKekBackupWithPop(id);
            } catch {
              try {
                const backup = wrapKekWithUmk(
                  kekRef,
                  auth.umk!,
                  id,
                  auth.user.id,
                  current_kek_version,
                );
                await encryptionApi.createKekBackupWithPop(id, {
                  key_version: current_kek_version,
                  encrypted_kek: base64UrlEncode(backup.encryptedKek),
                  nonce: base64UrlEncode(backup.nonce),
                });
              } catch {
                /* fire-and-forget */
              }
            }
          })();
        }
      } else {
        if (!auth.identityKeys || !auth.umk) {
          throw new Error("Identity keys or UMK not available for KEK recovery.");
        }

        const envelope = await encryptionApi.getMemberEnvelopeWithPop(id);
        if (envelope && envelope.sender_ecdh_public_key && envelope.sender_signing_public_key) {
          const meSenderEcdhPk = base64UrlDecode(envelope.sender_ecdh_public_key);
          const meSenderSigningPk = base64UrlDecode(envelope.sender_signing_public_key);

          const meTofuResult = await verifyTofu(
            envelope.sender_user_id,
            envelope.sender_device_id,
            meSenderSigningPk,
            meSenderEcdhPk,
          );
          if (
            meTofuResult.status === "identity_key_changed" ||
            meTofuResult.status === "ecdh_key_mismatch"
          ) {
            throw new Error("Key verification failed for member envelope sender.");
          }
          await handleTofuResult(meTofuResult);

          kek = decryptKekFromMemberEnvelope(
            base64UrlDecode(envelope.encrypted_kek),
            base64UrlDecode(envelope.nonce),
            auth.identityKeys.ecdhPrivate,
            meSenderEcdhPk,
            id,
            auth.user.id,
            envelope.key_version,
            envelope.sender_device_id,
          );

          const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
          const deviceEnvelope = encryptKekForDevice(
            kek,
            device.deviceEcdhPrivate,
            deviceEcdhPublic,
            id,
            auth.user.id,
            deviceId,
            deviceId,
            current_kek_version,
          );
          await encryptionApi.createWorkspaceKeyWithPop(id, {
            device_id: deviceId,
            sender_device_id: deviceId,
            key_version: current_kek_version,
            encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
            nonce: base64UrlEncode(deviceEnvelope.nonce),
          });

          const umkBackup = wrapKekWithUmk(kek, auth.umk, id, auth.user.id, current_kek_version);
          await encryptionApi.createKekBackupWithPop(id, {
            key_version: current_kek_version,
            encrypted_kek: base64UrlEncode(umkBackup.encryptedKek),
            nonce: base64UrlEncode(umkBackup.nonce),
          });
        } else {
          let backupData: { encrypted_kek: string; nonce: string; key_version: number };
          try {
            backupData = await encryptionApi.getKekBackupWithPop(id);
          } catch {
            throw new Error(
              "KEK recovery not available. No device envelope, member envelope, or UMK backup found.",
            );
          }

          kek = unwrapKekFromBackup(
            base64UrlDecode(backupData.encrypted_kek),
            base64UrlDecode(backupData.nonce),
            auth.umk,
            id,
            auth.user.id,
            backupData.key_version,
          );

          const deviceEcdhPublic = x25519.getPublicKey(device.deviceEcdhPrivate);
          const deviceEnvelope = encryptKekForDevice(
            kek,
            device.deviceEcdhPrivate,
            deviceEcdhPublic,
            id,
            auth.user.id,
            deviceId,
            deviceId,
            current_kek_version,
          );
          await encryptionApi.createWorkspaceKeyWithPop(id, {
            device_id: deviceId,
            sender_device_id: deviceId,
            key_version: current_kek_version,
            encrypted_kek: base64UrlEncode(deviceEnvelope.ciphertext),
            nonce: base64UrlEncode(deviceEnvelope.nonce),
          });
        }
      }

      const tokenBytes = randomBytes(32);
      const tokenBase64 = base64UrlEncode(tokenBytes);
      const tokenHashBytes = sha256(tokenBytes);
      const tokenHash = base64UrlEncode(tokenHashBytes);
      const tokenPrefix = tokenBase64.slice(0, 4);

      const invitationId = crypto.randomUUID();

      const { encryptedKek, nonce } = encryptKekForInvitation(
        kek,
        tokenBytes,
        id,
        invitationId,
        current_kek_version,
      );

      const expiresAt = new Date(
        Date.now() + inviteExpiryDays() * 24 * 60 * 60 * 1000,
      ).toISOString();

      await workspacesApi.createInvitation(id, {
        invitation_id: invitationId,
        token_hash: tokenHash,
        token_prefix: tokenPrefix,
        encrypted_kek: base64UrlEncode(encryptedKek),
        kek_nonce: base64UrlEncode(nonce),
        kek_version: current_kek_version,
        role_id: inviteRoleId() || null,
        invited_email: email,
        expires_at: expiresAt,
      });

      const link = `${window.location.origin}/invite#token=${tokenBase64}`;
      setInviteLink(link);

      queryClient.invalidateQueries({
        queryKey: ["workspace-invitations", id],
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create invitation");
    } finally {
      setInviting(false);
    }
  };

  const handleCopyLink = async () => {
    const link = inviteLink();
    if (!link) return;
    await navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const resetInviteDialog = () => {
    setShowInvite(false);
    setInviteEmail("");
    setInviteRoleId("");
    setInviteExpiryDays(7);
    setInviteLink(null);
    setCopied(false);
  };

  const handleRevokeInvitation = async (invitationId: string) => {
    const id = wsId();
    if (!id) return;
    setError(null);
    try {
      await workspacesApi.revokeInvitation(id, invitationId);
      queryClient.invalidateQueries({
        queryKey: ["workspace-invitations", id],
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke invitation");
    }
  };

  // ─── Roles CRUD ──────────────────────────────────────────────
  const [showCreateRole, setShowCreateRole] = createSignal(false);
  const [createRoleName, setCreateRoleName] = createSignal("");
  const [createBaseRole, setCreateBaseRole] = createSignal<"admin" | "editor" | "viewer">("editor");
  const [creatingRole, setCreatingRole] = createSignal(false);

  const [editRoleTarget, setEditRoleTarget] = createSignal<{
    id: string;
    name: string;
    base_role: string;
    is_default: boolean;
    permissions: PermissionOverride[];
  } | null>(null);
  const [editRoleName, setEditRoleName] = createSignal("");
  const [editPermissions, setEditPermissions] = createSignal<Record<string, boolean | null>>({});
  const [savingRole, setSavingRole] = createSignal(false);

  const [deleteRoleTarget, setDeleteRoleTarget] = createSignal<{
    id: string;
    name: string;
  } | null>(null);
  const [deletingRole, setDeletingRole] = createSignal(false);

  const handleCreateRole = async () => {
    const name = createRoleName().trim();
    const id = wsId();
    if (!name || !id) return;
    setCreatingRole(true);
    setError(null);
    try {
      await workspacesApi.createRole(id, {
        name,
        base_role: createBaseRole(),
      });
      setShowCreateRole(false);
      setCreateRoleName("");
      setCreateBaseRole("editor");
      queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create role");
    } finally {
      setCreatingRole(false);
    }
  };

  const openEditRole = (role: {
    id: string;
    name: string;
    base_role: string;
    is_default: boolean;
    permissions?: PermissionOverride[];
  }) => {
    setEditRoleTarget({
      id: role.id,
      name: role.name,
      base_role: role.base_role,
      is_default: role.is_default,
      permissions: role.permissions ?? [],
    });
    setEditRoleName(role.name);
    const overrides: Record<string, boolean | null> = {};
    for (const p of role.permissions ?? []) {
      overrides[p.permission] = p.granted;
    }
    setEditPermissions(overrides);
  };

  const handleSaveRole = async () => {
    const target = editRoleTarget();
    const id = wsId();
    if (!target || !id) return;
    setSavingRole(true);
    setError(null);
    try {
      const overrides = editPermissions();
      const permissions: PermissionOverride[] = [];
      for (const [key, val] of Object.entries(overrides)) {
        if (val !== null) {
          permissions.push({ permission: key, granted: val });
        }
      }
      const baseRole = target.base_role as BaseRole;
      for (const p of target.permissions) {
        if (!(p.permission in overrides)) {
          permissions.push({
            permission: p.permission,
            granted: defaultGrant(baseRole, p.permission as Permission),
          });
        }
      }
      await workspacesApi.updateRole(id, target.id, {
        name: editRoleName().trim() || undefined,
        permissions,
      });
      setEditRoleTarget(null);
      queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update role");
    } finally {
      setSavingRole(false);
    }
  };

  const handleDeleteRole = async () => {
    const target = deleteRoleTarget();
    const id = wsId();
    if (!target || !id) return;
    setDeletingRole(true);
    setError(null);
    try {
      const res = await workspacesApi.deleteRole(id, target.id);
      setDeleteRoleTarget(null);
      queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
      queryClient.invalidateQueries({ queryKey: ["workspace-invitations", id] });
      const count = (res as any)?.invalidated_invitation_count;
      if (count && count > 0) {
        setInfo(`Role deleted. ${count} invitation(s) were invalidated.`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete role");
    } finally {
      setDeletingRole(false);
    }
  };

  const handleSetDefault = async (roleId: string) => {
    const id = wsId();
    if (!id) return;
    setError(null);
    try {
      await workspacesApi.updateRole(id, roleId, { is_default: true });
      queryClient.invalidateQueries({ queryKey: ["workspace-roles", id] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to set default role");
    }
  };

  const togglePermission = (permKey: string) => {
    const current = editPermissions();
    const currentVal = current[permKey];
    if (currentVal === undefined || currentVal === null) {
      setEditPermissions({ ...current, [permKey]: true });
    } else if (currentVal === true) {
      setEditPermissions({ ...current, [permKey]: false });
    } else {
      const next = { ...current };
      delete next[permKey];
      setEditPermissions(next);
    }
  };

  const permissionState = (permKey: string): "default" | "granted" | "denied" => {
    const val = editPermissions()[permKey];
    if (val === true) return "granted";
    if (val === false) return "denied";
    return "default";
  };

  const canEditPermission = (ceiling: string, roleBaseRole: string): boolean => {
    return isAtOrAbove(roleBaseRole as BaseRole, ceiling as BaseRole);
  };

  // ─── UI helpers ──────────────────────────────────────────────
  const roleBadgeClass = (baseRole: string) => {
    switch (baseRole) {
      case "owner":
        return "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-200";
      case "admin":
        return "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-200";
      case "editor":
        return "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-200";
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-200";
    }
  };

  // ─── Render ──────────────────────────────────────────────────
  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">Workspace</h3>
        <p class="text-sm text-muted-foreground">
          Manage workspace settings, members, roles, and invitations.
        </p>
      </div>

      <Show
        when={wsId()}
        fallback={<p class="text-sm text-muted-foreground">No workspace selected.</p>}
      >
        <Show when={error()}>
          {(err) => (
            <Alert variant="destructive">
              <AlertDescription>{err()}</AlertDescription>
            </Alert>
          )}
        </Show>

        <Show when={info()}>
          {(msg) => (
            <Alert>
              <AlertDescription>{msg()}</AlertDescription>
            </Alert>
          )}
        </Show>

        {/* ─── Workspace Info ───────────────────────────────── */}
        <Show
          when={!workspace.isLoading}
          fallback={
            <div class="flex justify-center py-4">
              <Spinner class="size-6" />
            </div>
          }
        >
          <section>
            <h4 class="text-sm font-medium mb-3">Info</h4>
            <div class="p-4 border border-border/60 bg-card space-y-3">
              <Show
                when={!editingName()}
                fallback={
                  <div class="flex items-center gap-2">
                    <Input
                      value={newName()}
                      onInput={(e) => setNewName(e.currentTarget.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleUpdateName();
                        if (e.key === "Escape") setEditingName(false);
                      }}
                      class="flex-1"
                    />
                    <Button size="sm" onClick={handleUpdateName} disabled={updating()}>
                      Save
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setEditingName(false)}>
                      Cancel
                    </Button>
                  </div>
                }
              >
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-xs text-muted-foreground">Name</p>
                    <p class="text-sm font-medium">{workspace.data?.name ?? "—"}</p>
                  </div>
                  <Show when={canUpdateWorkspace()}>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        setNewName(workspace.data?.name ?? "");
                        setEditingName(true);
                      }}
                    >
                      Edit
                    </Button>
                  </Show>
                </div>
              </Show>
              {/* Description */}
              <div>
                <Show
                  when={editingDescription()}
                  fallback={
                    <div class="flex items-center justify-between">
                      <div>
                        <p class="text-xs text-muted-foreground">Description</p>
                        <p class="text-sm text-muted-foreground">
                          {workspace.data?.description || "No description"}
                        </p>
                      </div>
                      <Show when={canUpdateWorkspace()}>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setNewDescription(workspace.data?.description ?? "");
                            setEditingDescription(true);
                          }}
                        >
                          Edit
                        </Button>
                      </Show>
                    </div>
                  }
                >
                  <div class="space-y-2">
                    <Field>
                      <FieldLabel>Description</FieldLabel>
                      <Input
                        value={newDescription()}
                        onInput={(e) => setNewDescription(e.currentTarget.value)}
                        placeholder="Workspace description"
                      />
                    </Field>
                    <div class="flex gap-2">
                      <Button size="sm" onClick={handleUpdateDescription} disabled={updating()}>
                        Save
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setEditingDescription(false)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </Show>
              </div>

              {/* Slug */}
              <div>
                <Show
                  when={editingSlug()}
                  fallback={
                    <div class="flex items-center justify-between">
                      <div>
                        <p class="text-xs text-muted-foreground">Slug</p>
                        <p class="text-sm font-mono">{workspace.data?.slug ?? "—"}</p>
                      </div>
                      <Show when={canUpdateWorkspace()}>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setNewSlug(workspace.data?.slug ?? "");
                            setEditingSlug(true);
                          }}
                        >
                          Edit
                        </Button>
                      </Show>
                    </div>
                  }
                >
                  <div class="space-y-2">
                    <Field>
                      <FieldLabel>Slug</FieldLabel>
                      <FieldDescription>
                        URL-safe identifier (lowercase letters, numbers, hyphens)
                      </FieldDescription>
                      <Input
                        value={newSlug()}
                        onInput={(e) => setNewSlug(e.currentTarget.value)}
                        placeholder="workspace-slug"
                      />
                    </Field>
                    <div class="flex gap-2">
                      <Button
                        size="sm"
                        onClick={handleUpdateSlug}
                        disabled={updating() || !newSlug().trim()}
                      >
                        Save
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => setEditingSlug(false)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                </Show>
              </div>
            </div>
          </section>

          <div class="border-t border-border/40" />

          {/* ─── Members ────────────────────────────────────── */}
          <section>
            <div class="flex items-center justify-between mb-3">
              <h4 class="text-sm font-medium">
                Members {!memberPermissionDenied() && `(${members.data?.members?.length ?? 0})`}
              </h4>
              <Show when={canInvite() && !workspace.data?.needs_kek_rotation}>
                <Button size="sm" onClick={() => setShowInvite(true)}>
                  <UserPlusIcon class="size-3 mr-1" />
                  Invite
                </Button>
              </Show>
            </div>
            <Show
              when={!memberPermissionDenied() && !members.isLoading}
              fallback={
                <Show when={!memberPermissionDenied()}>
                  <div class="flex justify-center py-4">
                    <Spinner class="size-4" />
                  </div>
                </Show>
              }
            >
              <div class="space-y-2">
                <For each={members.data?.members}>
                  {(member) => {
                    const isSelf = () => member.user_id === currentUserId();
                    return (
                      <div class="flex items-center justify-between p-2 border border-border/40">
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-2">
                            <span class="text-sm font-medium truncate">{member.name}</span>
                            <Show when={isSelf()}>
                              <span class="text-xs text-muted-foreground">(you)</span>
                            </Show>
                            <span
                              class={`text-xs px-1.5 py-0.5 rounded-full ${roleBadgeClass(member.base_role)}`}
                            >
                              {member.role_name}
                            </span>
                          </div>
                          <div class="text-xs text-muted-foreground truncate">{member.email}</div>
                        </div>
                        <div class="flex items-center gap-1">
                          <Show
                            when={canChangeRole() && (member.base_role !== "owner" || isOwner())}
                          >
                            <Button
                              variant="ghost"
                              size="icon"
                              class="size-7"
                              title="Change role"
                              onClick={() => {
                                setRoleChangeTarget({
                                  user_id: member.user_id,
                                  name: member.name,
                                  current_role_id: member.role_id,
                                });
                                setSelectedRoleId(member.role_id);
                              }}
                            >
                              <ShieldIcon class="size-3" />
                            </Button>
                          </Show>
                          <Show
                            when={
                              isSelf() ||
                              (canRemoveMember() && (member.base_role !== "owner" || isOwner()))
                            }
                          >
                            <Button
                              variant="ghost"
                              size="icon"
                              class="size-7"
                              title={isSelf() ? "Leave workspace" : "Remove member"}
                              onClick={() =>
                                setRemoveTarget({
                                  user_id: member.user_id,
                                  name: member.name,
                                })
                              }
                            >
                              <UserMinusIcon class="size-3" />
                            </Button>
                          </Show>
                        </div>
                      </div>
                    );
                  }}
                </For>
              </div>
            </Show>
          </section>

          <div class="border-t border-border/40" />

          {/* ─── Roles ──────────────────────────────────────── */}
          <section>
            <div class="flex items-center justify-between mb-3">
              <h4 class="text-sm font-medium">Roles</h4>
              <Show when={canManageRoles()}>
                <Button size="sm" onClick={() => setShowCreateRole(true)}>
                  <PlusIcon class="size-3 mr-1" />
                  New Role
                </Button>
              </Show>
            </div>
            <Show
              when={!roles.isLoading}
              fallback={
                <div class="flex justify-center py-4">
                  <Spinner class="size-4" />
                </div>
              }
            >
              <div class="space-y-2">
                <For each={roles.data?.roles}>
                  {(role) => (
                    <div class="flex items-center justify-between p-2 border border-border/40">
                      <div class="flex items-center gap-2">
                        <ShieldIcon class="size-3" />
                        <span class="text-sm font-medium">{role.name}</span>
                        <span class="text-xs px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground">
                          {role.base_role}
                        </span>
                        <Show when={role.is_default}>
                          <span class="text-xs px-1.5 py-0.5 rounded-full bg-primary/10 text-primary">
                            Default
                          </span>
                        </Show>
                      </div>
                      <Show when={canManageRoles()}>
                        <div class="flex items-center gap-1">
                          <Show when={role.catalog_version != null}>
                            <Button
                              variant="ghost"
                              size="icon"
                              class="size-7"
                              title="Edit role"
                              onClick={() => openEditRole(role)}
                            >
                              <PencilIcon class="size-3" />
                            </Button>
                          </Show>
                          <Show when={!role.is_default && isOwner()}>
                            <Button
                              variant="ghost"
                              size="icon"
                              class="size-7"
                              title="Set as default"
                              onClick={() => handleSetDefault(role.id)}
                            >
                              <StarIcon class="size-3" />
                            </Button>
                          </Show>
                          <Show when={role.catalog_version != null && !role.is_default}>
                            <Button
                              variant="ghost"
                              size="icon"
                              class="size-7"
                              title="Delete role"
                              onClick={() =>
                                setDeleteRoleTarget({
                                  id: role.id,
                                  name: role.name,
                                })
                              }
                            >
                              <TrashIcon class="size-3" />
                            </Button>
                          </Show>
                        </div>
                      </Show>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </section>

          <div class="border-t border-border/40" />

          {/* ─── Invitations ────────────────────────────────── */}
          <Show when={canInvite() && invitations.data?.invitations?.length}>
            <section>
              <h4 class="text-sm font-medium mb-3 flex items-center gap-2">
                <MailIcon class="size-4" />
                Pending Invitations
              </h4>
              <div class="space-y-2">
                <For each={invitations.data?.invitations}>
                  {(inv) => (
                    <div class="flex items-center justify-between p-2 border border-border/40">
                      <div>
                        <div class="flex items-center gap-2 text-sm font-medium">
                          {inv.invited_email}
                          <span class="font-mono text-xs text-muted-foreground">
                            {inv.token_prefix}
                          </span>
                        </div>
                        <div class="text-xs text-muted-foreground">
                          {inv.role_name ?? "Default role"} &middot; Expires{" "}
                          {new Date(inv.expires_at).toLocaleDateString()}
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        class="size-7"
                        title="Revoke invitation"
                        onClick={() => handleRevokeInvitation(inv.invitation_id)}
                      >
                        <TrashIcon class="size-3" />
                      </Button>
                    </div>
                  )}
                </For>
              </div>
            </section>
            <div class="border-t border-border/40" />
          </Show>

          {/* ─── Danger zone ────────────────────────────────── */}
          <section class="space-y-3">
            <h4 class="text-sm font-medium">Danger Zone</h4>
            <div class="flex gap-2">
              <Show
                when={
                  !isOwner() ||
                  (members.data?.members?.filter((m) => m.base_role === "owner").length ?? 0) > 1
                }
              >
                <Button size="sm" variant="outline" onClick={() => setShowLeave(true)}>
                  Leave Workspace
                </Button>
              </Show>
              <Show when={isOwner()}>
                <Button size="sm" variant="destructive" onClick={() => setShowDelete(true)}>
                  Delete Workspace
                </Button>
              </Show>
            </div>
          </section>
        </Show>
      </Show>

      {/* ─── Dialogs ──────────────────────────────────────────── */}

      {/* Invite Dialog */}
      <Dialog
        open={showInvite()}
        onOpenChange={(open: boolean) => {
          if (!open) resetInviteDialog();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Invite Member</DialogTitle>
            <DialogDescription>Send an invitation to join this workspace.</DialogDescription>
          </DialogHeader>
          <Show
            when={!inviteLink()}
            fallback={
              <div class="space-y-3">
                <p class="text-sm text-muted-foreground">
                  Invitation created. Share this link with the invitee:
                </p>
                <div class="flex items-center gap-2">
                  <Input value={inviteLink() ?? ""} readOnly class="font-mono text-xs" />
                  <Button variant="outline" size="icon" onClick={handleCopyLink}>
                    <Show when={copied()} fallback={<CopyIcon class="size-4" />}>
                      <CheckIcon class="size-4" />
                    </Show>
                  </Button>
                </div>
                <DialogFooter>
                  <Button onClick={resetInviteDialog}>Done</Button>
                </DialogFooter>
              </div>
            }
          >
            <div class="space-y-4">
              <Field>
                <FieldLabel for="invite-email">Email</FieldLabel>
                <Input
                  id="invite-email"
                  type="email"
                  placeholder="user@example.com"
                  value={inviteEmail()}
                  onInput={(e) => setInviteEmail(e.currentTarget.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleInvite();
                  }}
                />
              </Field>
              <Show when={assignableRoles().length > 0}>
                <Field>
                  <FieldLabel for="invite-role">Role</FieldLabel>
                  <Show when={defaultRoleAssignable()}>
                    <FieldDescription>Leave empty for the default role.</FieldDescription>
                  </Show>
                  <Select
                    options={assignableRoles()}
                    optionValue="id"
                    optionTextValue="name"
                    value={assignableRoles().find((r: any) => r.id === inviteRoleId()) ?? null}
                    onChange={(val: any) => setInviteRoleId(val?.id ?? "")}
                    placeholder={defaultRoleAssignable() ? "Default role" : "Select a role"}
                    itemComponent={(itemProps: any) => (
                      <SelectItem item={itemProps.item}>
                        {itemProps.item.rawValue.name} ({itemProps.item.rawValue.base_role})
                      </SelectItem>
                    )}
                  >
                    <SelectTrigger>
                      <SelectValue>
                        {(state: any) => {
                          const opt = state.selectedOption();
                          return opt ? `${opt.name} (${opt.base_role})` : "";
                        }}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent />
                  </Select>
                </Field>
              </Show>
              <Field>
                <FieldLabel for="invite-expiry">Expires in</FieldLabel>
                <select
                  id="invite-expiry"
                  class="flex h-9 w-full border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors"
                  value={inviteExpiryDays()}
                  onChange={(e) => setInviteExpiryDays(Number(e.currentTarget.value))}
                >
                  <option value={1}>1 day</option>
                  <option value={3}>3 days</option>
                  <option value={7}>7 days</option>
                  <option value={14}>14 days</option>
                  <option value={30}>30 days</option>
                </select>
              </Field>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={resetInviteDialog}>
                Cancel
              </Button>
              <Button
                onClick={handleInvite}
                disabled={
                  inviting() ||
                  !inviteEmail().trim() ||
                  (!defaultRoleAssignable() && !inviteRoleId())
                }
              >
                {inviting() ? "Creating..." : "Create Invitation"}
              </Button>
            </DialogFooter>
          </Show>
        </DialogContent>
      </Dialog>

      {/* Remove Member Dialog */}
      <Dialog
        open={!!removeTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) setRemoveTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {removeTarget()?.user_id === currentUserId() ? "Leave Workspace" : "Remove Member"}
            </DialogTitle>
            <DialogDescription>
              {removeTarget()?.user_id === currentUserId()
                ? "Are you sure you want to leave this workspace?"
                : `Remove ${removeTarget()?.name} from this workspace?`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRemoveTarget(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleRemoveMember} disabled={removing()}>
              {removing()
                ? "Removing..."
                : removeTarget()?.user_id === currentUserId()
                  ? "Leave"
                  : "Remove"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Change Role Dialog */}
      <Dialog
        open={!!roleChangeTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) setRoleChangeTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change Role</DialogTitle>
            <DialogDescription>Select a new role for {roleChangeTarget()?.name}.</DialogDescription>
          </DialogHeader>
          <Show when={assignableRoles().length > 0}>
            <Field>
              <FieldLabel for="role-select">Role</FieldLabel>
              <Select
                options={assignableRoles()}
                optionValue="id"
                optionTextValue="name"
                value={assignableRoles().find((r: any) => r.id === selectedRoleId()) ?? null}
                onChange={(val: any) => setSelectedRoleId(val?.id ?? "")}
                disallowEmptySelection
                itemComponent={(itemProps: any) => (
                  <SelectItem item={itemProps.item}>
                    {itemProps.item.rawValue.name} ({itemProps.item.rawValue.base_role})
                  </SelectItem>
                )}
              >
                <SelectTrigger>
                  <SelectValue>
                    {(state: any) => {
                      const opt = state.selectedOption();
                      return opt ? `${opt.name} (${opt.base_role})` : "";
                    }}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent />
              </Select>
            </Field>
          </Show>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRoleChangeTarget(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleChangeRole}
              disabled={changingRole() || selectedRoleId() === roleChangeTarget()?.current_role_id}
            >
              {changingRole() ? "Changing..." : "Change Role"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Role Dialog */}
      <Dialog open={showCreateRole()} onOpenChange={setShowCreateRole}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Role</DialogTitle>
            <DialogDescription>Create a new custom role for this workspace.</DialogDescription>
          </DialogHeader>
          <div class="space-y-4">
            <Field>
              <FieldLabel for="role-name">Name</FieldLabel>
              <Input
                id="role-name"
                placeholder="Custom Role"
                value={createRoleName()}
                onInput={(e) => setCreateRoleName(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreateRole();
                }}
              />
            </Field>
            <Field>
              <FieldLabel for="base-role">Base Role</FieldLabel>
              <Select
                options={["admin", "editor", "viewer"]}
                value={createBaseRole()}
                onChange={(val: any) => setCreateBaseRole(val as "admin" | "editor" | "viewer")}
                disallowEmptySelection
                itemComponent={(itemProps: any) => (
                  <SelectItem item={itemProps.item}>
                    {itemProps.item.rawValue.charAt(0).toUpperCase() +
                      itemProps.item.rawValue.slice(1)}
                  </SelectItem>
                )}
              >
                <SelectTrigger>
                  <SelectValue>
                    {(state: any) => {
                      const opt = state.selectedOption();
                      return opt ? opt.charAt(0).toUpperCase() + opt.slice(1) : "";
                    }}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent />
              </Select>
            </Field>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateRole(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreateRole}
              disabled={creatingRole() || !createRoleName().trim()}
            >
              {creatingRole() ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Role Dialog */}
      <Dialog
        open={!!editRoleTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) setEditRoleTarget(null);
        }}
      >
        <DialogContent class="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Role: {editRoleTarget()?.name}</DialogTitle>
            <DialogDescription>
              Modify role name and permissions. Click a permission to cycle: default, granted,
              denied.
            </DialogDescription>
          </DialogHeader>
          <div class="space-y-4">
            <Field>
              <FieldLabel for="edit-role-name">Name</FieldLabel>
              <Input
                id="edit-role-name"
                value={editRoleName()}
                onInput={(e) => setEditRoleName(e.currentTarget.value)}
              />
            </Field>
            <div class="space-y-2">
              <p class="text-sm font-medium">Permissions</p>
              <div class="space-y-1">
                <For each={[...ALL_PERMISSIONS]}>
                  {(permKey) => {
                    const editable = () =>
                      canEditPermission(CEILING[permKey], editRoleTarget()?.base_role ?? "viewer");
                    const state = () => permissionState(permKey);
                    return (
                      <button
                        class={`flex items-center justify-between w-full px-3 py-2 text-sm border transition-colors ${
                          !editable()
                            ? "opacity-40 cursor-not-allowed"
                            : "cursor-pointer hover:bg-muted/50"
                        } ${
                          state() === "granted"
                            ? "border-green-300 bg-green-50 dark:border-green-800 dark:bg-green-900/20"
                            : state() === "denied"
                              ? "border-red-300 bg-red-50 dark:border-red-800 dark:bg-red-900/20"
                              : "border-border"
                        }`}
                        disabled={!editable()}
                        onClick={() => togglePermission(permKey)}
                        type="button"
                      >
                        <span>{PERMISSION_LABELS[permKey]}</span>
                        <span class="text-xs text-muted-foreground">
                          {state() === "granted"
                            ? "Granted"
                            : state() === "denied"
                              ? "Denied"
                              : "Default"}
                        </span>
                      </button>
                    );
                  }}
                </For>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditRoleTarget(null)}>
              Cancel
            </Button>
            <Button onClick={handleSaveRole} disabled={savingRole()}>
              {savingRole() ? "Saving..." : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Role Dialog */}
      <Dialog
        open={!!deleteRoleTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) setDeleteRoleTarget(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Role</DialogTitle>
            <DialogDescription>
              Delete the role &ldquo;{deleteRoleTarget()?.name}&rdquo;? Members using this role will
              need to be reassigned first.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteRoleTarget(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDeleteRole} disabled={deletingRole()}>
              {deletingRole() ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Workspace Dialog */}
      <Dialog open={showDelete()} onOpenChange={setShowDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Workspace</DialogTitle>
            <DialogDescription>
              This action cannot be undone. All documents and data in this workspace will be
              permanently deleted.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDelete(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting()}>
              {deleting() ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Leave Workspace Dialog */}
      <Dialog open={showLeave()} onOpenChange={setShowLeave}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Leave Workspace</DialogTitle>
            <DialogDescription>
              You will lose access to all documents in this workspace.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowLeave(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleLeave} disabled={leaving()}>
              {leaving() ? "Leaving..." : "Leave"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
