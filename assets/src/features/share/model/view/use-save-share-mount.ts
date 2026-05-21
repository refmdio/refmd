import { createEffect, createMemo, createSignal } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import { readCachedDecryptedTitle } from "@/entities/document";
import type { ShareLinkMount } from "@/entities/mount";
import {
  mountedShareSessionKey,
  readShareUrlFragmentFromLocation,
  readWorkspacePinBootstrapHashFromLocation,
  rememberMountTrustAnchor,
} from "@/entities/mount";
import { authState } from "@/entities/session";
import { currentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { sharesApi } from "@/shared/api";
import {
  readShareSessionTrustAnchor,
  rememberMountedShareParticipantSession,
} from "../../lib/session/session";

export interface SaveShareMountOptions {
  shareSlug: string;
  targetKind: "document" | "folder";
  targetToken: string | null;
  targetDocumentId?: string | null;
  targetTitle?: string | null;
  existingMounts?: ShareLinkMount[];
  sessionAvailable?: boolean;
  onSaved?: () => void;
}

export function useSaveShareMount(props: SaveShareMountOptions) {
  const queryClient = useQueryClient();
  const { allWorkspaces } = useWorkspaces();
  const [saving, setSaving] = createSignal(false);
  const [savedMountId, setSavedMountId] = createSignal<string | null>(null);
  const workspaces = createMemo(() =>
    allWorkspaces().map((workspace) => ({
      id: workspace.id,
      name: workspace.name,
    })),
  );
  const directWorkspaceId = createMemo(() => {
    const list = workspaces();
    if (list.length !== 1) return null;
    const current = currentWorkspaceId();
    if (current && list.some((workspace) => workspace.id === current)) return current;
    return list[0]?.id ?? null;
  });
  const existingMount = createMemo(() =>
    props.existingMounts?.find(
      (mount) => mount.target_kind === props.targetKind && mount.target_token === props.targetToken,
    ),
  );
  const isSaved = () => !!savedMountId() || !!existingMount();
  const hasSession = () => props.sessionAvailable ?? !!authState();
  const [storedWorkspacePinBootstrapHash, setStoredWorkspacePinBootstrapHash] = createSignal<
    string | null
  >(null);
  const [hasStoredShareDekEncryptionKey, setHasStoredShareDekEncryptionKey] = createSignal(false);
  const [hasStoredShareSessionAnchor, setHasStoredShareSessionAnchor] = createSignal(false);
  const workspacePinBootstrapHash = () =>
    readWorkspacePinBootstrapHashFromLocation() ?? storedWorkspacePinBootstrapHash();
  const hasSaveMaterial = () =>
    hasSession() &&
    !!props.targetToken &&
    !!workspacePinBootstrapHash() &&
    (!!readShareUrlFragmentFromLocation() ||
      (hasStoredShareSessionAnchor() && hasStoredShareDekEncryptionKey())) &&
    !isSaved();
  const canSaveToWorkspace = (workspaceId: string | null | undefined) =>
    hasSaveMaterial() && !!workspaceId;
  const canSave = () => canSaveToWorkspace(directWorkspaceId());
  const canChooseWorkspace = () => hasSaveMaterial() && workspaces().length > 1;
  const hasDestinationWorkspace = () => workspaces().length > 0;
  const targetTitle = () =>
    (props.targetDocumentId ? readCachedDecryptedTitle(props.targetDocumentId) : null) ??
    props.targetTitle ??
    null;

  const loadStoredTrustAnchor = async () => {
    const anchor = await readShareSessionTrustAnchor(props.shareSlug);
    setStoredWorkspacePinBootstrapHash(anchor.workspacePinBootstrapHash);
    setHasStoredShareDekEncryptionKey(anchor.hasShareDekEncryptionKey);
    setHasStoredShareSessionAnchor(!!anchor.anchor);
  };

  createEffect(() => {
    if (!hasSession() || !props.shareSlug) return;
    void loadStoredTrustAnchor();
  });

  const save = async (workspaceId?: string): Promise<boolean> => {
    await loadStoredTrustAnchor();
    const destinationWorkspaceId = workspaceId ?? directWorkspaceId();
    if (!canSaveToWorkspace(destinationWorkspaceId)) return false;
    setSaving(true);
    try {
      const mount = await sharesApi.createShareMount({
        workspace_id: destinationWorkspaceId!,
        share_slug: props.shareSlug,
        target_kind: props.targetKind,
        target_token: props.targetToken!,
        authenticated_workspace_pin_bootstrap_hash: workspacePinBootstrapHash()!,
      });
      const mountSessionKey = mountedShareSessionKey(mount.id);
      await rememberMountedShareParticipantSession({
        sourceShareSlug: props.shareSlug,
        mountSessionKey,
        shareId: mount.share_id,
      });
      await rememberMountTrustAnchor({
        mountId: mount.id,
        shareId: mount.share_id,
        shareSessionKey: mountSessionKey,
        targetToken: props.targetToken!,
        targetKind: props.targetKind,
        targetTitle: targetTitle(),
        workspacePinBootstrapHash: workspacePinBootstrapHash()!,
      });
      setSavedMountId(mount.id);
      await queryClient.invalidateQueries({
        queryKey: ["share-mounts", destinationWorkspaceId],
      });
      props.onSaved?.();
      return true;
    } catch (err) {
      const conflict = err as {
        data?: { mount?: { id?: string; share_id?: string } };
        body?: { mount?: { id?: string; share_id?: string } };
      };
      const mountId = conflict.data?.mount?.id ?? conflict.body?.mount?.id;
      if (mountId) {
        const mount = conflict.data?.mount ?? conflict.body?.mount;
        if (mount?.share_id && props.targetToken && workspacePinBootstrapHash()) {
          const mountSessionKey = mountedShareSessionKey(mountId);
          await rememberMountedShareParticipantSession({
            sourceShareSlug: props.shareSlug,
            mountSessionKey,
            shareId: mount.share_id,
          });
          await rememberMountTrustAnchor({
            mountId,
            shareId: mount.share_id,
            shareSessionKey: mountSessionKey,
            targetToken: props.targetToken,
            targetKind: props.targetKind,
            targetTitle: targetTitle(),
            workspacePinBootstrapHash: workspacePinBootstrapHash()!,
          });
        }
        setSavedMountId(mountId);
        props.onSaved?.();
        return true;
      } else {
        throw err;
      }
    } finally {
      setSaving(false);
    }
  };

  const title = () =>
    hasSession()
      ? isSaved()
        ? "Already saved"
        : !hasDestinationWorkspace()
          ? "No destination workspace"
          : !workspacePinBootstrapHash()
            ? "Open the original share link to save"
            : canChooseWorkspace()
              ? "Choose workspace"
              : "Add to workspace"
      : "Sign in to save";

  return {
    canSave,
    canChooseWorkspace,
    hasDestinationWorkspace,
    isSaved,
    save,
    saving,
    title,
    workspaces,
  };
}
