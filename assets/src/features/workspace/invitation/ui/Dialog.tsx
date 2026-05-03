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
} from "../model/useManagement";

interface WorkspaceInvitationDialogProps {
  state: WorkspaceInvitationManagementModel;
}

const INVITATION_EXPIRY_OPTIONS = [
  { value: "1", label: "1 day" },
  { value: "3", label: "3 days" },
  { value: "7", label: "7 days" },
  { value: "14", label: "14 days" },
  { value: "30", label: "30 days" },
];

function expiryLabel(value: string): string {
  return INVITATION_EXPIRY_OPTIONS.find((option) => option.value === value)?.label ?? "";
}

function RoleNameValue() {
  return (
    <SelectValue>
      {(selectState: unknown) => {
        const state = selectState as { selectedOption: () => WorkspaceInvitationRoleOption | null };
        const option = state.selectedOption();
        return (option ? `${option.name} (${option.base_role})` : "") as unknown as Element;
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
                  itemComponent={(itemProps) => {
                    const role = itemProps.item.rawValue as WorkspaceInvitationRoleOption;
                    return (
                      <SelectItem item={itemProps.item}>
                        {role.name} ({role.base_role})
                      </SelectItem>
                    );
                  }}
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
              <Select
                options={INVITATION_EXPIRY_OPTIONS.map((option) => option.value)}
                value={state().expiryDays().toString()}
                onChange={(value: string | null) => {
                  if (value) state().setExpiryDays(Number(value));
                }}
                disallowEmptySelection
                itemComponent={(itemProps) => (
                  <SelectItem item={itemProps.item}>
                    {expiryLabel(itemProps.item.rawValue as string)}
                  </SelectItem>
                )}
              >
                <SelectTrigger id="invite-expiry" class="w-full">
                  <SelectValue>{() => expiryLabel(state().expiryDays().toString())}</SelectValue>
                </SelectTrigger>
                <SelectContent />
              </Select>
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
