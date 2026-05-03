import { For, Show } from "solid-js";
import { UserPlusIcon, TrashIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Switch } from "@/shared/ui/switch";
import type { GuestInvitationManagementModel } from "../model/useManagement";

interface GuestInvitationsSectionProps {
  state: GuestInvitationManagementModel;
}

export function GuestInvitationsSection(props: GuestInvitationsSectionProps) {
  const state = () => props.state;

  return (
    <Show when={state().canManageGuestInvitations() || state().canUpdateWorkspace()}>
      <section class="space-y-3" data-testid="guest-invites-section">
        <div class="flex items-center justify-between">
          <h4 class="text-sm font-medium flex items-center gap-2">
            <UserPlusIcon class="size-4" />
            Guest Invites
          </h4>
          <Show when={state().canManageGuestInvitations() && state().guestInvitesEnabled()}>
            <Button size="sm" variant="outline" onClick={state().openDialog}>
              Invite Guest
            </Button>
          </Show>
        </div>

        <Show when={state().canUpdateWorkspace()}>
          <div class="p-3 border border-border/60 bg-card space-y-3">
            <div class="flex items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium">Allow guest invites</p>
                <p class="text-xs text-muted-foreground">Disable this to block new guest links.</p>
              </div>
              <Switch
                aria-label="Allow guest invites"
                checked={state().settingsEnabled()}
                onChange={(checked: boolean) => state().setSettingsEnabled(checked)}
              />
            </div>
            <div class="grid gap-2 sm:grid-cols-[1fr_auto] sm:items-end">
              <Field>
                <FieldLabel for="guest-member-limit">Guest member limit</FieldLabel>
                <Input
                  id="guest-member-limit"
                  type="number"
                  min="1"
                  placeholder="No limit"
                  value={state().settingsLimit()}
                  onInput={(event) => state().setSettingsLimit(event.currentTarget.value)}
                />
              </Field>
              <Button
                size="sm"
                onClick={state().updateSettings}
                disabled={state().updatingSettings()}
              >
                {state().updatingSettings() ? "Saving..." : "Save"}
              </Button>
            </div>
          </div>
        </Show>

        <Show when={state().canManageGuestInvitations()}>
          <Show
            when={(state().invitations.data?.invitations?.length ?? 0) > 0}
            fallback={<p class="text-sm text-muted-foreground">No guest invitations.</p>}
          >
            <div class="space-y-2">
              <For each={state().invitations.data?.invitations}>
                {(invitation) => (
                  <div class="flex items-center justify-between p-2 border border-border/40">
                    <div>
                      <div class="flex items-center gap-2 text-sm font-medium">
                        <span>{invitation.permission}</span>
                        <span class="font-mono text-xs text-muted-foreground">
                          {invitation.token_prefix}
                        </span>
                      </div>
                      <div class="text-xs text-muted-foreground">
                        Workspace guest &middot; Created{" "}
                        {new Date(invitation.created_at).toLocaleDateString()} &middot;{" "}
                        {invitation.redemption_count}/{invitation.max_redemptions} redemptions
                        {" · "}
                        Expires {new Date(invitation.expires_at).toLocaleDateString()}
                        {invitation.revoked_at ? " · Revoked" : ""}
                      </div>
                    </div>
                    <Show when={!invitation.revoked_at && state().guestInvitesEnabled()}>
                      <Button
                        variant="ghost"
                        size="icon"
                        class="size-7"
                        title="Revoke invitation"
                        onClick={() => state().revokeInvitation(invitation.invitation_id)}
                      >
                        <TrashIcon class="size-3" />
                      </Button>
                    </Show>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </Show>
      </section>
      <div class="border-t border-border/40" />
    </Show>
  );
}
