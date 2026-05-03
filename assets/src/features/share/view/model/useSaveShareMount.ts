import { createMemo, createSignal } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import type { ShareMountLookupItem } from "@/entities/mount";
import { authState } from "@/entities/session";
import { currentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { sharesApi } from "@/shared/api";

export interface SaveShareMountOptions {
  shareSlug: string;
  targetKind: "document" | "folder";
  targetToken: string | null;
  existingMounts?: ShareMountLookupItem[];
  sessionAvailable?: boolean;
  onSaved?: () => void;
}

export function useSaveShareMount(props: SaveShareMountOptions) {
  const queryClient = useQueryClient();
  const { allWorkspaces } = useWorkspaces();
  const [saving, setSaving] = createSignal(false);
  const [savedMountId, setSavedMountId] = createSignal<string | null>(null);
  const workspaceId = createMemo(() => {
    const current = currentWorkspaceId();
    if (current) return current;
    return allWorkspaces()[0]?.id ?? null;
  });
  const existingMount = createMemo(() =>
    props.existingMounts?.find(
      (mount) => mount.target_kind === props.targetKind && mount.target_token === props.targetToken,
    ),
  );
  const isSaved = () => !!savedMountId() || !!existingMount();
  const hasSession = () => props.sessionAvailable ?? !!authState();
  const canSave = () => hasSession() && !!workspaceId() && !!props.targetToken && !isSaved();

  const save = async () => {
    if (!canSave()) return;

    setSaving(true);
    try {
      const mount = await sharesApi.createShareMount({
        workspace_id: workspaceId()!,
        share_slug: props.shareSlug,
        target_kind: props.targetKind,
        target_token: props.targetToken!,
        parent_id: null,
      });
      setSavedMountId(mount.id);
      await queryClient.invalidateQueries({
        queryKey: ["share-mounts", workspaceId()],
      });
      props.onSaved?.();
    } catch (err) {
      const conflict = err as {
        data?: { mount?: { id?: string } };
        body?: { mount?: { id?: string } };
      };
      const mountId = conflict.data?.mount?.id ?? conflict.body?.mount?.id;
      if (mountId) {
        setSavedMountId(mountId);
        props.onSaved?.();
      }
    } finally {
      setSaving(false);
    }
  };

  const title = () =>
    hasSession() ? (isSaved() ? "Already saved" : "Add to workspace") : "Sign in to save";

  return {
    canSave,
    isSaved,
    save,
    saving,
    title,
  };
}
