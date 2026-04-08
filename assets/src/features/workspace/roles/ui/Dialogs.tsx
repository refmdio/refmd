import { For } from "solid-js";
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
import { Input } from "@/shared/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";
import { ALL_PERMISSIONS, CEILING, PERMISSION_LABELS } from "@/entities/workspace";
import type { WorkspaceRoleManagementModel } from "../model/useManagement";

interface WorkspaceRoleManagementDialogsProps {
  state: WorkspaceRoleManagementModel;
}

type BaseRoleOption = "admin" | "editor" | "viewer";

function isBaseRoleOption(value: string | null): value is BaseRoleOption {
  return value === "admin" || value === "editor" || value === "viewer";
}

export function WorkspaceRoleManagementDialogs(props: WorkspaceRoleManagementDialogsProps) {
  return (
    <>
      <Dialog
        open={props.state.createDialogOpen()}
        onOpenChange={(open: boolean) => {
          if (!open) props.state.closeCreateRoleDialog();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Role</DialogTitle>
            <DialogDescription>Create a new custom role for this workspace.</DialogDescription>
          </DialogHeader>
          <div class="space-y-4">
            <Field>
              <FieldLabel for="role-name">Name</FieldLabel>
              <Input
                id="role-name"
                placeholder="Custom Role"
                value={props.state.createRoleName()}
                onInput={(event) => props.state.setCreateRoleName(event.currentTarget.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") props.state.handleCreateRole();
                }}
              />
            </Field>
            <Field>
              <FieldLabel for="base-role">Base Role</FieldLabel>
              <Select
                options={["admin", "editor", "viewer"]}
                value={props.state.createBaseRole()}
                onChange={(value: string | null) => {
                  if (isBaseRoleOption(value)) {
                    props.state.setCreateBaseRole(value);
                  }
                }}
                disallowEmptySelection
                itemComponent={(itemProps) => {
                  const role = itemProps.item.rawValue as BaseRoleOption;
                  return (
                    <SelectItem item={itemProps.item}>
                      {role.charAt(0).toUpperCase() + role.slice(1)}
                    </SelectItem>
                  );
                }}
              >
                <SelectTrigger>
                  <SelectValue>
                    {(selectState: unknown) => {
                      const state = selectState as {
                        selectedOption: () => BaseRoleOption | null;
                      };
                      const option = state.selectedOption();
                      return (option
                        ? option.charAt(0).toUpperCase() + option.slice(1)
                        : "") as unknown as Element;
                    }}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent />
              </Select>
            </Field>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={props.state.closeCreateRoleDialog}>
              Cancel
            </Button>
            <Button
              onClick={props.state.handleCreateRole}
              disabled={props.state.creatingRole() || !props.state.createRoleName().trim()}
            >
              {props.state.creatingRole() ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!props.state.editRoleTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) props.state.closeEditRoleDialog();
        }}
      >
        <DialogContent class="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Role: {props.state.editRoleTarget()?.name}</DialogTitle>
            <DialogDescription>
              Modify role name and permissions. Click a permission to cycle: default, granted,
              denied.
            </DialogDescription>
          </DialogHeader>
          <div class="space-y-4">
            <Field>
              <FieldLabel for="edit-role-name">Name</FieldLabel>
              <Input
                id="edit-role-name"
                value={props.state.editRoleName()}
                onInput={(event) => props.state.setEditRoleName(event.currentTarget.value)}
              />
            </Field>
            <div class="space-y-2">
              <p class="text-sm font-medium">Permissions</p>
              <div class="space-y-1">
                <For each={[...ALL_PERMISSIONS]}>
                  {(permissionKey) => {
                    const editable = () =>
                      props.state.canEditPermission(
                        CEILING[permissionKey],
                        props.state.editRoleTarget()?.base_role ?? "viewer",
                      );
                    const permissionState = () => props.state.permissionState(permissionKey);

                    return (
                      <button
                        class={`flex items-center justify-between w-full px-3 py-2 text-sm border transition-colors ${
                          !editable()
                            ? "opacity-40 cursor-not-allowed"
                            : "cursor-pointer hover:bg-muted/50"
                        } ${
                          permissionState() === "granted"
                            ? "border-green-300 bg-green-50 dark:border-green-800 dark:bg-green-900/20"
                            : permissionState() === "denied"
                              ? "border-red-300 bg-red-50 dark:border-red-800 dark:bg-red-900/20"
                              : "border-border"
                        }`}
                        disabled={!editable()}
                        onClick={() => props.state.togglePermission(permissionKey)}
                        type="button"
                      >
                        <span>{PERMISSION_LABELS[permissionKey]}</span>
                        <span class="text-xs text-muted-foreground">
                          {permissionState() === "granted"
                            ? "Granted"
                            : permissionState() === "denied"
                              ? "Denied"
                              : "Default"}
                        </span>
                      </button>
                    );
                  }}
                </For>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={props.state.closeEditRoleDialog}>
              Cancel
            </Button>
            <Button onClick={props.state.handleSaveRole} disabled={props.state.savingRole()}>
              {props.state.savingRole() ? "Saving..." : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={!!props.state.deleteRoleTarget()}
        onOpenChange={(open: boolean) => {
          if (!open) props.state.closeDeleteRoleDialog();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Role</DialogTitle>
            <DialogDescription>
              Delete the role &ldquo;{props.state.deleteRoleTarget()?.name}&rdquo;? Members using
              this role will need to be reassigned first.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={props.state.closeDeleteRoleDialog}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={props.state.handleDeleteRole}
              disabled={props.state.deletingRole()}
            >
              {props.state.deletingRole() ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
