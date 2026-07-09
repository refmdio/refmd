import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { AlertTriangleIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";
import { RecoveryKeySavePanel } from "@/shared/lib/recovery/recovery-key-save-panel";
import { useRegisterPage } from "../../model/register/use-register-page";
import { OAuthProviderButtons } from "../oauth/OAuthProviderButtons";

export function RegisterPage() {
  const state = useRegisterPage();

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Show
        when={!state.recoveryMnemonic()}
        fallback={
          <Card class="w-full max-w-lg">
            <CardHeader class="space-y-1">
              <CardTitle class="text-2xl font-bold">Recovery Key</CardTitle>
              <CardDescription>
                Save this recovery key in a safe place. You will need it for account recovery if you
                lose access to all your devices.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RecoveryKeySavePanel
                mnemonic={() => state.recoveryMnemonic()!}
                confirmed={state.mnemonicConfirmed}
                visible={state.showMnemonic}
                onToggleVisible={() => state.setShowMnemonic(!state.showMnemonic())}
                onCopy={state.handleCopyRecoveryKey}
                onDownload={state.handleDownloadRecoveryKey}
                onContinue={state.handleConfirmMnemonic}
                warningDescription="If you lose this recovery key and forget your password, you will permanently lose access to your encrypted data."
              />
            </CardContent>
          </Card>
        }
      >
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1">
            <CardTitle class="text-2xl font-bold">Create Account</CardTitle>
            <CardDescription>Enter your details to create a new account</CardDescription>
          </CardHeader>
          <CardContent>
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
                <FieldLabel for="name">Name</FieldLabel>
                <Input
                  id="name"
                  type="text"
                  placeholder="John Doe"
                  value={state.name()}
                  onInput={(e) => state.setName(e.currentTarget.value)}
                  required
                  disabled={state.loading()}
                  autocomplete="name"
                />
              </Field>

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
                  autocomplete="new-password"
                />
              </Field>

              <Field>
                <FieldLabel for="confirm-password">Confirm Password</FieldLabel>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="--------"
                  value={state.confirmPassword()}
                  onInput={(e) => state.setConfirmPassword(e.currentTarget.value)}
                  required
                  disabled={state.loading()}
                  autocomplete="new-password"
                />
              </Field>

              <Button type="submit" class="w-full" disabled={state.loading()}>
                {state.loading() ? (
                  <span class="flex items-center gap-2">
                    <Spinner class="size-3" /> Creating account...
                  </span>
                ) : (
                  "Create Account"
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
                Already have an account?{" "}
                <A href="/auth/login" class="text-primary hover:underline">
                  Sign in
                </A>
              </p>
            </form>
          </CardContent>
        </Card>
      </Show>
    </main>
  );
}
