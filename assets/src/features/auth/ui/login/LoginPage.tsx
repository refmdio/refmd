import { createSignal, Show } from "solid-js";
import { A } from "@solidjs/router";
import { AlertTriangleIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Label } from "@/shared/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Checkbox } from "@/shared/ui/checkbox";
import { Spinner } from "@/shared/ui/spinner";
import { useLoginPage } from "../../model/login/use-login-page";
import { OAuthProviderButtons } from "../oauth/OAuthProviderButtons";
import {
  isSecureLogoutIncomplete,
  retrySecureLogoutCleanup,
} from "@/shared/lib/auth/logout-incomplete";

export function LoginPage() {
  const state = useLoginPage();
  const [cleanupRequired, setCleanupRequired] = createSignal(isSecureLogoutIncomplete());
  const [cleanupPending, setCleanupPending] = createSignal(false);
  const [cleanupError, setCleanupError] = createSignal<string | null>(null);

  const retryCleanup = async () => {
    setCleanupPending(true);
    setCleanupError(null);
    try {
      await retrySecureLogoutCleanup();
      setCleanupRequired(false);
    } catch {
      setCleanupError("Secure cleanup is still incomplete.");
    } finally {
      setCleanupPending(false);
    }
  };

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-md">
        <CardHeader class="space-y-1">
          <CardTitle class="text-2xl font-bold">Login</CardTitle>
          <CardDescription>Enter your credentials to access your account</CardDescription>
        </CardHeader>
        <CardContent>
          <Show
            when={!cleanupRequired()}
            fallback={
              <div class="space-y-4">
                <Alert variant="destructive">
                  <AlertTriangleIcon />
                  <AlertDescription>
                    Secure logout did not finish. Sign-in is blocked until local cleanup succeeds.
                  </AlertDescription>
                </Alert>
                <Show when={cleanupError()}>
                  {(error) => <p class="text-sm text-destructive">{error()}</p>}
                </Show>
                <Button class="w-full" disabled={cleanupPending()} onClick={retryCleanup}>
                  {cleanupPending() ? "Cleaning..." : "Retry secure cleanup"}
                </Button>
              </div>
            }
          >
            <form onSubmit={state.handleSubmit} class="space-y-4">
              <Show when={state.error()}>
                {(err) => (
                  <Alert variant="destructive">
                    <AlertTriangleIcon />
                    <AlertDescription>{err()}</AlertDescription>
                  </Alert>
                )}
              </Show>

              <Field>
                <FieldLabel for="email">Email</FieldLabel>
                <Input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  value={state.email()}
                  onInput={(e) => state.setEmail(e.currentTarget.value)}
                  required
                  disabled={state.loading()}
                  autocomplete="email"
                />
              </Field>

              <Field>
                <FieldLabel for="password">Password</FieldLabel>
                <Input
                  id="password"
                  type="password"
                  placeholder="--------"
                  value={state.password()}
                  onInput={(e) => state.setPassword(e.currentTarget.value)}
                  required
                  disabled={state.loading()}
                  autocomplete="current-password"
                />
              </Field>

              <div class="flex items-center space-x-2">
                <Checkbox
                  id="remember"
                  checked={state.rememberMe()}
                  onChange={(checked: boolean) => state.setRememberMe(checked)}
                  disabled={state.loading()}
                />
                <Label for="remember" class="text-xs font-sans normal-case tracking-normal">
                  Keep me signed in
                </Label>
              </div>

              <Button type="submit" class="w-full" disabled={state.loading()}>
                {state.loading() ? (
                  <span class="flex items-center gap-2">
                    <Spinner class="size-3" /> Signing in...
                  </span>
                ) : (
                  "Sign In"
                )}
              </Button>

              <Show when={state.oauthProviders().length > 0}>
                <>
                  <div class="flex items-center gap-3 text-xs text-muted-foreground">
                    <div class="h-px flex-1 bg-border" />
                    <span>or</span>
                    <div class="h-px flex-1 bg-border" />
                  </div>

                  <OAuthProviderButtons
                    providers={state.oauthProviders()}
                    loadingProvider={state.oauthLoading()}
                    disabled={state.loading()}
                    onStart={state.handleOAuthStart}
                  />
                </>
              </Show>

              <p class="text-center text-sm text-muted-foreground">
                Don't have an account?{" "}
                <A href="/auth/register" class="text-primary hover:underline">
                  Register
                </A>
              </p>
            </form>
          </Show>
        </CardContent>
      </Card>
    </main>
  );
}
