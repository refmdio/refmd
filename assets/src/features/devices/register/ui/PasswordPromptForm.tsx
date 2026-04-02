import { Show, type Accessor } from "solid-js";
import { AlertTriangleIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

interface PasswordPromptFormProps {
  description: string;
  error: Accessor<string | null>;
  loading: Accessor<boolean>;
  value: Accessor<string>;
  fieldId: string;
  onInput: (value: string) => void;
  onSubmit: (event: Event) => Promise<void>;
}

export function PasswordPromptForm(props: PasswordPromptFormProps) {
  return (
    <form onSubmit={props.onSubmit} class="space-y-4">
      <p class="text-sm text-muted-foreground">{props.description}</p>
      <Show when={props.error()}>
        {(currentError) => (
          <Alert variant="destructive">
            <AlertTriangleIcon />
            <AlertDescription>{currentError()}</AlertDescription>
          </Alert>
        )}
      </Show>
      <Field>
        <FieldLabel for={props.fieldId}>Password</FieldLabel>
        <Input
          id={props.fieldId}
          type="password"
          placeholder="--------"
          value={props.value()}
          onInput={(inputEvent) => props.onInput(inputEvent.currentTarget.value)}
          required
          disabled={props.loading()}
          autocomplete="current-password"
        />
      </Field>
      <Button type="submit" class="w-full" disabled={props.loading()}>
        {props.loading() ? (
          <span class="flex items-center gap-2">
            <Spinner class="size-3" /> Verifying...
          </span>
        ) : (
          "Continue"
        )}
      </Button>
    </form>
  );
}
