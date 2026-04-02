import { Match, Show, Switch } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { KeyRoundIcon, AlertTriangleIcon, CheckCircleIcon } from "lucide-solid";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";
import { usePasswordResetPage } from "../model/usePasswordResetPage";

export function PasswordResetPage() {
  const navigate = useNavigate();
  const state = usePasswordResetPage();

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-md">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <KeyRoundIcon class="size-6" />
            Reset Password
          </CardTitle>
          <CardDescription>Enter your email to receive a password reset link.</CardDescription>
        </CardHeader>
        <CardContent>
          <Switch>
            <Match when={state.phase() === "request" || state.phase() === "error"}>
              <form onSubmit={state.handleRequest} class="space-y-4">
                <Show when={state.error()}>
                  {(err) => (
                    <Alert variant="destructive">
                      <AlertTriangleIcon />
                      <AlertDescription>{err()}</AlertDescription>
                    </Alert>
                  )}
                </Show>
                <Field>
                  <FieldLabel for="reset-email">Email</FieldLabel>
                  <Input
                    id="reset-email"
                    type="email"
                    placeholder="you@example.com"
                    value={state.email()}
                    onInput={(e) => state.setEmail(e.currentTarget.value)}
                    required
                    disabled={state.loading()}
                    autocomplete="email"
                  />
                </Field>
                <Button type="submit" class="w-full" disabled={state.loading()}>
                  {state.loading() ? (
                    <span class="flex items-center gap-2">
                      <Spinner class="size-3" /> Sending...
                    </span>
                  ) : (
                    "Send Reset Link"
                  )}
                </Button>
                <div class="text-center">
                  <a
                    href="/auth/login"
                    class="text-sm text-muted-foreground hover:text-primary underline"
                  >
                    Back to Login
                  </a>
                </div>
              </form>
            </Match>

            <Match when={state.phase() === "sent"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <CheckCircleIcon class="size-10 text-green-500" />
                <p class="text-sm text-muted-foreground text-center">
                  If an account exists with that email, we sent a password reset link. Check your
                  inbox and click the link to continue.
                </p>
                <Button variant="outline" onClick={() => navigate("/auth/login")}>
                  Back to Login
                </Button>
              </div>
            </Match>

            <Match when={state.phase() === "verifying"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <Spinner class="size-6" />
                <p class="text-sm text-muted-foreground">Verifying your reset link...</p>
              </div>
            </Match>
          </Switch>
        </CardContent>
      </Card>
    </main>
  );
}
