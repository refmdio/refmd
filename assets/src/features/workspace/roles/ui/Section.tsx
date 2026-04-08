import { For, Show } from "solid-js";
import { PencilIcon, PlusIcon, ShieldIcon, StarIcon, TrashIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import type { components } from "@/shared/api";
import type { WorkspaceRoleManagementModel } from "../model/useManagement";

type WorkspaceRole = components["schemas"]["RoleResponse"];

interface WorkspaceRolesSectionProps {
  roles: WorkspaceRole[] | undefined;
  isLoading: boolean;
  canManageRoles: boolean;
  isOwner: boolean;
  management: WorkspaceRoleManagementModel;
}

export function WorkspaceRolesSection(props: WorkspaceRolesSectionProps) {
  return (
    <section>
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-sm font-medium">Roles</h4>
        <Show when={props.canManageRoles}>
          <Button size="sm" onClick={props.management.openCreateRoleDialog}>
            <PlusIcon class="size-3 mr-1" />
            New Role
          </Button>
        </Show>
      </div>
      <Show
        when={!props.isLoading}
        fallback={
          <div class="flex justify-center py-4">
            <Spinner class="size-4" />
          </div>
        }
      >
        <div class="space-y-2">
          <For each={props.roles}>
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
                <Show when={props.canManageRoles}>
                  <div class="flex items-center gap-1">
                    <Show when={role.catalog_version != null}>
                      <Button
                        variant="ghost"
                        size="icon"
                        class="size-7"
                        title="Edit role"
                        onClick={() => props.management.openEditRole(role)}
                      >
                        <PencilIcon class="size-3" />
                      </Button>
                    </Show>
                    <Show when={!role.is_default && props.isOwner}>
                      <Button
                        variant="ghost"
                        size="icon"
                        class="size-7"
                        title="Set as default"
                        onClick={() => props.management.handleSetDefault(role.id)}
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
                        onClick={() => props.management.openDeleteRoleDialog(role)}
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
  );
}
