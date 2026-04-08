import { For, Show } from "solid-js";
import { ShieldIcon, UserMinusIcon, UserPlusIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import type { components } from "@/shared/api";
import type { WorkspaceMemberManagementModel } from "../model/useManagement";

type WorkspaceMember = components["schemas"]["MemberInfo"];

interface WorkspaceMembersSectionProps {
  members: WorkspaceMember[] | undefined;
  isLoading: boolean;
  memberPermissionDenied: boolean;
  canInvite: boolean;
  canChangeRole: boolean;
  canRemoveMember: boolean;
  isOwner: boolean;
  needsKekRotation: boolean | undefined;
  onOpenInviteDialog: () => void;
  management: WorkspaceMemberManagementModel;
}

function roleBadgeClass(baseRole: string) {
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
}

export function WorkspaceMembersSection(props: WorkspaceMembersSectionProps) {
  return (
    <section>
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-sm font-medium">
          Members {!props.memberPermissionDenied && `(${props.members?.length ?? 0})`}
        </h4>
        <Show when={props.canInvite && !props.needsKekRotation}>
          <Button size="sm" onClick={props.onOpenInviteDialog}>
            <UserPlusIcon class="size-3 mr-1" />
            Invite
          </Button>
        </Show>
      </div>
      <Show
        when={!props.memberPermissionDenied && !props.isLoading}
        fallback={
          <Show when={!props.memberPermissionDenied}>
            <div class="flex justify-center py-4">
              <Spinner class="size-4" />
            </div>
          </Show>
        }
      >
        <div class="space-y-2">
          <For each={props.members}>
            {(member) => {
              const isSelf = () => member.user_id === props.management.currentUserId();

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
                      when={props.canChangeRole && (member.base_role !== "owner" || props.isOwner)}
                    >
                      <Button
                        variant="ghost"
                        size="icon"
                        class="size-7"
                        title="Change role"
                        onClick={() => props.management.openRoleChangeDialog(member)}
                      >
                        <ShieldIcon class="size-3" />
                      </Button>
                    </Show>
                    <Show
                      when={
                        isSelf() ||
                        (props.canRemoveMember && (member.base_role !== "owner" || props.isOwner))
                      }
                    >
                      <Button
                        variant="ghost"
                        size="icon"
                        class="size-7"
                        title={isSelf() ? "Leave workspace" : "Remove member"}
                        onClick={() => props.management.openRemoveMemberDialog(member)}
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
  );
}
