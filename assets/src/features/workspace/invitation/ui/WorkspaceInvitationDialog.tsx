import { Show } from "solid-js";
import { CheckIcon, CopyIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";
import type {
  WorkspaceInvitationManagementModel,
  WorkspaceInvitationRoleOption,
} from "../model/useWorkspaceInvitationManagement";

interface WorkspaceInvitationDialogProps {
  state: WorkspaceInvitationManagementModel;
}

type InvitationRoleSelectState = {
  selectedOption: () => WorkspaceInvitationRoleOption | null;
};

type InvitationRoleItemProps = {
  item: { rawValue: WorkspaceInvitationRoleOption };
};

function RoleNameValue() {
  return (
    <SelectValue>
      {(selectState: InvitationRoleSelectState) => {
        const option = selectState.selectedOption();
        return option ? `${option.name} (${option.base_role})` : "";
      }}
    </SelectValue>
  );
}

export function WorkspaceInvitationDialog(props: WorkspaceInvitationDialogProps) {
  const state = () => props.state;

  return (
    <Dialog
      open={state().inviteDialogOpen()}
      onOpenChange={(open: boolean) => {
        if (!open) state().resetInviteState();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite Member</DialogTitle>
          <DialogDescription>Send an invitation to join this workspace.</DialogDescription>
        </DialogHeader>
        <Show
          when={!state().inviteLink()}
          fallback={
            <div class="space-y-3">
              <p class="text-sm text-muted-foreground">
                Invitation created. Share this link with the invitee:
              </p>
              <div class="flex items-center gap-2">
                <Input value={state().inviteLink() ?? ""} readOnly class="font-mono text-xs" />
                <Button variant="outline" size="icon" onClick={state().copyInviteLink}>
                  <Show when={state().copied()} fallback={<CopyIcon class="size-4" />}>
                    <CheckIcon class="size-4" />
                  </Show>
                </Button>
              </div>
              <DialogFooter>
                <Button onClick={state().resetInviteState}>Done</Button>
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
                value={state().inviteEmail()}
                onInput={(event) => state().setInviteEmail(event.currentTarget.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") state().createInvitation();
                }}
              />
            </Field>
            <Show when={state().assignableRoles().length > 0}>
              <Field>
                <FieldLabel for="invite-role">Role</FieldLabel>
                <Show when={state().defaultRoleAssignable()}>
                  <FieldDescription>Leave empty for the default role.</FieldDescription>
                </Show>
                <Select
                  options={state().assignableRoles()}
                  optionValue="id"
                  optionTextValue="name"
                  value={
                    state()
                      .assignableRoles()
                      .find((role) => role.id === state().selectedRoleId()) ?? null
                  }
                  onChange={(value: WorkspaceInvitationRoleOption | null) =>
                    state().setSelectedRoleId(value?.id ?? "")
                  }
                  placeholder={state().defaultRoleAssignable() ? "Default role" : "Select a role"}
                  itemComponent={(itemProps: InvitationRoleItemProps) => (
                    <SelectItem item={itemProps.item}>
                      {itemProps.item.rawValue.name} ({itemProps.item.rawValue.base_role})
                    </SelectItem>
                  )}
                >
                  <SelectTrigger>
                    <RoleNameValue />
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
                value={state().expiryDays()}
                onChange={(event) => state().setExpiryDays(Number(event.currentTarget.value))}
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
            <Button variant="outline" onClick={state().resetInviteState}>
              Cancel
            </Button>
            <Button
              onClick={state().createInvitation}
              disabled={
                state().isInviting() ||
                !state().inviteEmail().trim() ||
                (!state().defaultRoleAssignable() && !state().selectedRoleId())
              }
            >
              {state().isInviting() ? "Creating..." : "Create Invitation"}
            </Button>
          </DialogFooter>
        </Show>
      </DialogContent>
    </Dialog>
  );
}
