import { Show } from "solid-js";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";
import type { WorkspaceMemberManagementModel } from "../../model/members/use-management";

interface WorkspaceMemberManagementDialogsProps {
  state: WorkspaceMemberManagementModel;
  assignableRoles: Array<{
    id: string;
    name: string;
    base_role: string;
  }>;
}

type AssignableRole = WorkspaceMemberManagementDialogsProps["assignableRoles"][number];

function RoleNameValue() {
  return (
    <SelectValue>
      {(selectState: unknown) => {
        const state = selectState as { selectedOption: () => AssignableRole | null };
        const option = state.selectedOption();
        return (option ? `${option.name} (${option.base_role})` : "") as unknown as Element;
      }}
    </SelectValue>
  );
}

export function WorkspaceMemberManagementDialogs(props: WorkspaceMemberManagementDialogsProps) {
  return (
    <>
      <Dialog
        open={!!props.state.removeTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) props.state.closeRemoveMemberDialog();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {props.state.removeTarget()?.user_id === props.state.currentUserId()
                ? "Leave Workspace"
                : "Remove Member"}
            </DialogTitle>
            <DialogDescription>
              {props.state.removeTarget()?.user_id === props.state.currentUserId()
                ? "Are you sure you want to leave this workspace?"
                : `Remove ${props.state.removeTarget()?.name} from this workspace?`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={props.state.closeRemoveMemberDialog}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={props.state.handleRemoveMember}
              disabled={props.state.removing()}
            >
              {props.state.removing()
                ? "Removing..."
                : props.state.removeTarget()?.user_id === props.state.currentUserId()
                  ? "Leave"
                  : "Remove"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!props.state.roleChangeTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) props.state.closeRoleChangeDialog();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change Role</DialogTitle>
            <DialogDescription>
              Select a new role for {props.state.roleChangeTarget()?.name}.
            </DialogDescription>
          </DialogHeader>
          <Show when={props.assignableRoles.length > 0}>
            <Field>
              <FieldLabel for="role-select">Role</FieldLabel>
              <Select
                options={props.assignableRoles}
                optionValue="id"
                optionTextValue="name"
                value={
                  props.assignableRoles.find((role) => role.id === props.state.selectedRoleId()) ??
                  null
                }
                onChange={(value: AssignableRole | null) =>
                  props.state.setSelectedRoleId(value?.id ?? "")
                }
                disallowEmptySelection
                itemComponent={(itemProps) => {
                  const role = itemProps.item.rawValue as AssignableRole;
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
          <DialogFooter>
            <Button variant="outline" onClick={props.state.closeRoleChangeDialog}>
              Cancel
            </Button>
            <Button
              onClick={props.state.handleChangeRole}
              disabled={
                props.state.changingRole() ||
                props.state.selectedRoleId() === props.state.roleChangeTarget()?.current_role_id
              }
            >
              {props.state.changingRole() ? "Changing..." : "Change Role"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
