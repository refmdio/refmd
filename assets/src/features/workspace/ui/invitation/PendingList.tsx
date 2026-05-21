import { For, Show } from "solid-js";
import { MailIcon, Trash2Icon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import type { WorkspaceInvitationManagementModel } from "../../model/invitation/use-management";

interface PendingWorkspaceInvitationListProps {
  state: WorkspaceInvitationManagementModel;
}

export function PendingWorkspaceInvitationList(props: PendingWorkspaceInvitationListProps) {
  const state = () => props.state;

  return (
    <Show when={state().hasPendingInvitations()}>
      <section>
        <h4 class="text-sm font-medium mb-3 flex items-center gap-2">
          <MailIcon class="size-4" />
          Pending Invitations
        </h4>
        <div class="space-y-2">
          <For each={state().invitations.data?.invitations ?? []}>
            {(invitation) => (
              <div class="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2">
                <div class="min-w-0">
                  <p class="truncate text-sm font-medium">{invitation.invited_email}</p>
                  <p class="text-xs text-muted-foreground">
                    {invitation.role_name ?? "Default role"} · {invitation.token_prefix}
                    {invitation.expires_at ? ` · Expires ${formatDate(invitation.expires_at)}` : ""}
                  </p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  aria-label={`Revoke invitation for ${invitation.invited_email}`}
                  onClick={() => void state().revokeInvitation(invitation.invitation_id)}
                >
                  <Trash2Icon class="size-4" />
                </Button>
              </div>
            )}
          </For>
        </div>
      </section>
      <div class="border-t border-border/40" />
    </Show>
  );
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(new Date(value));
}
