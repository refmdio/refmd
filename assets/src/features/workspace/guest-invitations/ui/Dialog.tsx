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
import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";
import type { GuestInvitationManagementModel } from "../model/useManagement";

interface GuestInvitationDialogProps {
  state: GuestInvitationManagementModel;
}

type SelectOption = { value: string; label: string };

const GUEST_PERMISSION_OPTIONS: SelectOption[] = [
  { value: "view", label: "View" },
  { value: "edit", label: "Edit" },
];

const GUEST_EXPIRY_OPTIONS: SelectOption[] = [
  { value: "1", label: "1 day" },
  { value: "7", label: "7 days" },
  { value: "14", label: "14 days" },
  { value: "30", label: "30 days" },
];

function optionLabel(options: SelectOption[], value: string): string {
  return options.find((option) => option.value === value)?.label ?? "";
}

function OptionSelect(props: {
  id?: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
}) {
  return (
    <Select
      options={props.options.map((option) => option.value)}
      value={props.value}
      onChange={(value: string | null) => props.onChange(value ?? "")}
      itemComponent={(itemProps) => (
        <SelectItem item={itemProps.item}>
          {optionLabel(props.options, itemProps.item.rawValue as string)}
        </SelectItem>
      )}
    >
      <SelectTrigger id={props.id} class="w-full">
        <SelectValue>{() => optionLabel(props.options, props.value)}</SelectValue>
      </SelectTrigger>
      <SelectContent />
    </Select>
  );
}

export function GuestInvitationDialog(props: GuestInvitationDialogProps) {
  const state = () => props.state;

  return (
    <Dialog
      open={state().dialogOpen()}
      onOpenChange={(open: boolean) => {
        if (!open) state().resetDialog();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite Guest</DialogTitle>
          <DialogDescription>
            Create an account-less guest invitation for this workspace.
          </DialogDescription>
        </DialogHeader>
        <Show
          when={!state().inviteLink()}
          fallback={
            <div class="space-y-3">
              <p class="text-sm text-muted-foreground">Guest invitation created.</p>
              <div class="flex items-center gap-2">
                <Input value={state().inviteLink() ?? ""} readOnly class="font-mono text-xs" />
                <Button variant="outline" size="icon" onClick={state().copyInviteLink}>
                  <Show when={state().copied()} fallback={<CopyIcon class="size-4" />}>
                    <CheckIcon class="size-4" />
                  </Show>
                </Button>
              </div>
              <DialogFooter>
                <Button onClick={state().resetDialog}>Done</Button>
              </DialogFooter>
            </div>
          }
        >
          <div class="grid gap-3 sm:grid-cols-2">
            <Field>
              <FieldLabel for="guest-permission">Permission</FieldLabel>
              <OptionSelect
                id="guest-permission"
                value={state().permission()}
                options={GUEST_PERMISSION_OPTIONS}
                onChange={(value) => state().setPermission(value as "view" | "edit")}
              />
            </Field>
            <Field>
              <FieldLabel for="guest-expiry">Expires in</FieldLabel>
              <OptionSelect
                id="guest-expiry"
                value={state().expiryDays().toString()}
                options={GUEST_EXPIRY_OPTIONS}
                onChange={(value) => state().setExpiryDays(Number(value))}
              />
            </Field>
            <Field>
              <FieldLabel for="guest-max-redemptions">Max redemptions</FieldLabel>
              <Input
                id="guest-max-redemptions"
                type="number"
                min="1"
                value={state().maxRedemptions()}
                onInput={(event) => state().setMaxRedemptions(event.currentTarget.value)}
              />
            </Field>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={state().resetDialog}>
              Cancel
            </Button>
            <Button onClick={state().createInvitation} disabled={state().creating()}>
              {state().creating() ? "Creating..." : "Create Invitation"}
            </Button>
          </DialogFooter>
        </Show>
      </DialogContent>
    </Dialog>
  );
}
