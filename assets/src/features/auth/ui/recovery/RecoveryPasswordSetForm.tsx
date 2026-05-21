import { Show } from "solid-js";
import { AlertTriangleIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

interface RecoveryPasswordSetFormProps {
  error: string | null;
  loading: boolean;
  newPassword: string;
  confirmPassword: string;
  onNewPasswordInput: (value: string) => void;
  onConfirmPasswordInput: (value: string) => void;
  onSubmit: (event: Event) => Promise<void>;
}

export function RecoveryPasswordSetForm(props: RecoveryPasswordSetFormProps) {
  return (
    <form onSubmit={props.onSubmit} class="space-y-4">
      <Show when={props.error}>
        {(currentError) => (
          <Alert variant="destructive">
            <AlertTriangleIcon />
            <AlertDescription>{currentError()}</AlertDescription>
          </Alert>
        )}
      </Show>
      <Field>
        <FieldLabel for="new-password">New Password</FieldLabel>
        <Input
          id="new-password"
          type="password"
          value={props.newPassword}
          onInput={(inputEvent) => props.onNewPasswordInput(inputEvent.currentTarget.value)}
          required
          disabled={props.loading}
          autocomplete="new-password"
        />
      </Field>
      <Field>
        <FieldLabel for="confirm-password">Confirm Password</FieldLabel>
        <Input
          id="confirm-password"
          type="password"
          value={props.confirmPassword}
          onInput={(inputEvent) => props.onConfirmPasswordInput(inputEvent.currentTarget.value)}
          required
          disabled={props.loading}
          autocomplete="new-password"
        />
      </Field>
      <Button type="submit" class="w-full" disabled={props.loading}>
        {props.loading ? (
          <span class="flex items-center gap-2">
            <Spinner class="size-3" /> Setting password...
          </span>
        ) : (
          "Set New Password"
        )}
      </Button>
    </form>
  );
}
