import { For, Show } from "solid-js";
import { MailIcon, TrashIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import type { WorkspaceInvitationManagementModel } from "../model/useManagement";

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
          <For each={state().invitations.data?.invitations}>
            {(invitation) => (
              <div class="flex items-center justify-between p-2 border border-border/40">
                <div>
                  <div class="flex items-center gap-2 text-sm font-medium">
                    {invitation.invited_email}
                    <span class="font-mono text-xs text-muted-foreground">
                      {invitation.token_prefix}
                    </span>
                  </div>
                  <div class="text-xs text-muted-foreground">
                    {invitation.role_name ?? "Default role"} &middot; Expires{" "}
                    {new Date(invitation.expires_at).toLocaleDateString()}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  class="size-7"
                  title="Revoke invitation"
                  onClick={() => state().revokeInvitation(invitation.invitation_id)}
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
  );
}
