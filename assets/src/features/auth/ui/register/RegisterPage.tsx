import { For, Show } from "solid-js";
import { A } from "@solidjs/router";
import { AlertTriangleIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";
import { useRegisterPage } from "../../model/register/use-register-page";

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
              <div class="space-y-4">
                <div class="p-4 border rounded">
                  <div class="flex items-center justify-between mb-3">
                    <span class="text-sm text-muted-foreground">24 words</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => state.setShowMnemonic(!state.showMnemonic())}
                    >
                      {state.showMnemonic() ? "Hide" : "Show"}
                    </Button>
                  </div>
                  <div class="grid grid-cols-3 gap-2 text-sm">
                    <For each={state.recoveryMnemonic()!.split(" ")}>
                      {(word, index) => (
                        <div class="flex items-center gap-2">
                          <span class="text-muted-foreground w-5 text-right">{index() + 1}.</span>
                          <span>{state.showMnemonic() ? word : "------"}</span>
                        </div>
                      )}
                    </For>
                  </div>
                </div>

                <div class="flex gap-2">
                  <Button onClick={state.handleCopyRecoveryKey} variant="outline" class="flex-1">
                    Copy
                  </Button>
                  <Button
                    onClick={state.handleDownloadRecoveryKey}
                    variant="outline"
                    class="flex-1"
                  >
                    Download
                  </Button>
                </div>

                <Alert variant="destructive">
                  <AlertTriangleIcon />
                  <AlertTitle>Warning</AlertTitle>
                  <AlertDescription>
                    If you lose this recovery key and forget your password, you will permanently
                    lose access to your encrypted data.
                  </AlertDescription>
                </Alert>

                <Button
                  onClick={state.handleConfirmMnemonic}
                  class="w-full"
                  disabled={!state.mnemonicConfirmed()}
                >
                  Continue
                </Button>
              </div>
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
