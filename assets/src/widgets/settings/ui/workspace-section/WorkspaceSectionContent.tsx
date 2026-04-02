import { Show } from "solid-js";
import {
  PendingWorkspaceInvitationList,
  WorkspaceMembersSection,
  WorkspaceRolesSection,
} from "@/features/workspace";
import { Button } from "@/shared/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";
import type { WorkspaceSectionModel } from "../../model/useWorkspaceSection";

interface WorkspaceSectionContentProps {
  state: WorkspaceSectionModel;
}

export function WorkspaceSectionContent(props: WorkspaceSectionContentProps) {
  const state = () => props.state;

  return (
    <Show
      when={!state().workspace.isLoading}
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
            when={!state().editingName()}
            fallback={
              <div class="flex items-center gap-2">
                <Input
                  value={state().newName()}
                  onInput={(event) => state().setNewName(event.currentTarget.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") state().handleUpdateName();
                    if (event.key === "Escape") state().setEditingName(false);
                  }}
                  class="flex-1"
                />
                <Button size="sm" onClick={state().handleUpdateName} disabled={state().updating()}>
                  Save
                </Button>
                <Button size="sm" variant="outline" onClick={() => state().setEditingName(false)}>
                  Cancel
                </Button>
              </div>
            }
          >
            <div class="flex items-center justify-between">
              <div>
                <p class="text-xs text-muted-foreground">Name</p>
                <p class="text-sm font-medium">{state().workspace.data?.name ?? "—"}</p>
              </div>
              <Show when={state().canUpdateWorkspace()}>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    state().setNewName(state().workspace.data?.name ?? "");
                    state().setEditingName(true);
                  }}
                >
                  Edit
                </Button>
              </Show>
            </div>
          </Show>

          <div>
            <Show
              when={state().editingDescription()}
              fallback={
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-xs text-muted-foreground">Description</p>
                    <p class="text-sm text-muted-foreground">
                      {state().workspace.data?.description || "No description"}
                    </p>
                  </div>
                  <Show when={state().canUpdateWorkspace()}>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        state().setNewDescription(state().workspace.data?.description ?? "");
                        state().setEditingDescription(true);
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
                    value={state().newDescription()}
                    onInput={(event) => state().setNewDescription(event.currentTarget.value)}
                    placeholder="Workspace description"
                  />
                </Field>
                <div class="flex gap-2">
                  <Button
                    size="sm"
                    onClick={state().handleUpdateDescription}
                    disabled={state().updating()}
                  >
                    Save
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => state().setEditingDescription(false)}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            </Show>
          </div>

          <div>
            <Show
              when={state().editingSlug()}
              fallback={
                <div class="flex items-center justify-between">
                  <div>
                    <p class="text-xs text-muted-foreground">Slug</p>
                    <p class="text-sm font-mono">{state().workspace.data?.slug ?? "—"}</p>
                  </div>
                  <Show when={state().canUpdateWorkspace()}>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        state().setNewSlug(state().workspace.data?.slug ?? "");
                        state().setEditingSlug(true);
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
                    value={state().newSlug()}
                    onInput={(event) => state().setNewSlug(event.currentTarget.value)}
                    placeholder="workspace-slug"
                  />
                </Field>
                <div class="flex gap-2">
                  <Button
                    size="sm"
                    onClick={state().handleUpdateSlug}
                    disabled={state().updating() || !state().newSlug().trim()}
                  >
                    Save
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => state().setEditingSlug(false)}>
                    Cancel
                  </Button>
                </div>
              </div>
            </Show>
          </div>
        </div>
      </section>

      <div class="border-t border-border/40" />

      <WorkspaceMembersSection
        members={state().memberManagement.members.data?.members}
        isLoading={state().memberManagement.members.isLoading}
        memberPermissionDenied={state().memberPermissionDenied()}
        canInvite={state().canInvite()}
        canChangeRole={state().canChangeRole()}
        canRemoveMember={state().canRemoveMember()}
        isOwner={state().isOwner()}
        needsKekRotation={state().workspace.data?.needs_kek_rotation}
        onOpenInviteDialog={state().invitationManagement.openInviteDialog}
        management={state().memberManagement}
      />

      <div class="border-t border-border/40" />

      <WorkspaceRolesSection
        roles={state().roleManagement.roles.data?.roles}
        isLoading={state().roleManagement.roles.isLoading}
        canManageRoles={state().canManageRoles()}
        isOwner={state().isOwner()}
        management={state().roleManagement}
      />

      <div class="border-t border-border/40" />

      <PendingWorkspaceInvitationList state={state().invitationManagement} />

      <section class="space-y-3">
        <h4 class="text-sm font-medium">Danger Zone</h4>
        <div class="flex gap-2">
          <Show
            when={
              !state().isOwner() ||
              (state().memberManagement.members.data?.members?.filter(
                (member) => member.base_role === "owner",
              ).length ?? 0) > 1
            }
          >
            <Button size="sm" variant="outline" onClick={() => state().setShowLeave(true)}>
              Leave Workspace
            </Button>
          </Show>
          <Show when={state().isOwner()}>
            <Button size="sm" variant="destructive" onClick={() => state().setShowDelete(true)}>
              Delete Workspace
            </Button>
          </Show>
        </div>
      </section>
    </Show>
  );
}
