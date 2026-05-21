import { createSignal, Show } from "solid-js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
import { AlertTriangleIcon } from "lucide-solid";
import { restoreKeysFromPassword } from "../../lib/session/restore-keys-from-password";

export default function PasswordReentryDialog(props: { open: boolean; onComplete: () => void }) {
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await restoreKeysFromPassword(password());
      props.onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Key restoration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={props.open}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Password Required</DialogTitle>
          <DialogDescription>
            Your encryption keys need to be restored. Please enter your password to continue.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} class="space-y-4">
          <Show when={error()}>
            {(err) => (
              <Alert variant="destructive">
                <AlertTriangleIcon />
                <AlertDescription>{err()}</AlertDescription>
              </Alert>
            )}
          </Show>

          <Field>
            <FieldLabel for="reentry-password">Password</FieldLabel>
            <Input
              id="reentry-password"
              type="password"
              placeholder="--------"
              value={password()}
              onInput={(e) => setPassword(e.currentTarget.value)}
              required
              disabled={loading()}
              autocomplete="current-password"
            />
          </Field>

          <DialogFooter>
            <Button type="submit" disabled={loading()}>
              {loading() ? (
                <span class="flex items-center gap-2">
                  <Spinner class="size-3" /> Restoring keys...
                </span>
              ) : (
                "Unlock"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
