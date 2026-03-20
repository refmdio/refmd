import { createSignal, Show, For } from "solid-js";
import { useNavigate, A } from "@solidjs/router";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";
import { register } from "@/features/auth";
import { setFullSession, setCryptoWorkerReady } from "@/shared/lib/auth-state";
import { AlertTriangleIcon } from "lucide-solid";
import { formatRecoveryKeyFile } from "@/shared/lib/recovery-key-format";

export default function RegisterPage() {
  const navigate = useNavigate();
  const [name, setName] = createSignal("");
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);
  const [recoveryMnemonic, setRecoveryMnemonic] = createSignal<string | null>(null);
  const [mnemonicConfirmed, setMnemonicConfirmed] = createSignal(false);
  const [showMnemonic, setShowMnemonic] = createSignal(false);
  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);

    if (password().length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password() !== confirmPassword()) {
      setError("Passwords do not match");
      return;
    }

    setLoading(true);
    try {
      const result = await register(email(), name(), password());
      setRecoveryMnemonic(result.recoveryMnemonic);

      setFullSession(
        {
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          identitySigningPublic: result.identitySigningPublic,
          identityEcdhPublic: result.identityEcdhPublic,
          expiresAt: null,
        },
        {
          deviceId: result.deviceId,
          deviceSigningPublic: result.deviceSigningPublic,
          deviceEcdhPublic: result.deviceEcdhPublic,
        },
      );

      if (result.workerReady) {
        setCryptoWorkerReady(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  const handleCopyRecoveryKey = async () => {
    const mnemonic = recoveryMnemonic();
    if (!mnemonic) return;
    try {
      await navigator.clipboard.writeText(mnemonic);
      setMnemonicConfirmed(true);
    } catch {
      // Clipboard write may fail (permissions, insecure context).
    }
  };

  const handleDownloadRecoveryKey = () => {
    const mnemonic = recoveryMnemonic();
    if (!mnemonic) return;

    const content = formatRecoveryKeyFile(mnemonic);

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "refmd-recovery-key.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setMnemonicConfirmed(true);
  };

  const handleConfirmMnemonic = () => {
    setPassword("");
    setConfirmPassword("");
    const pendingInvite = sessionStorage.getItem("refmd_invite_token");
    navigate(pendingInvite ? "/invite" : "/dashboard");
  };

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Show
        when={!recoveryMnemonic()}
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
                      onClick={() => setShowMnemonic(!showMnemonic())}
                    >
                      {showMnemonic() ? "Hide" : "Show"}
                    </Button>
                  </div>
                  <div class="grid grid-cols-3 gap-2 text-sm">
                    <For each={recoveryMnemonic()!.split(" ")}>
                      {(word, index) => (
                        <div class="flex items-center gap-2">
                          <span class="text-muted-foreground w-5 text-right">{index() + 1}.</span>
                          <span>{showMnemonic() ? word : "------"}</span>
                        </div>
                      )}
                    </For>
                  </div>
                </div>

                <div class="flex gap-2">
                  <Button onClick={handleCopyRecoveryKey} variant="outline" class="flex-1">
                    Copy
                  </Button>
                  <Button onClick={handleDownloadRecoveryKey} variant="outline" class="flex-1">
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
                  onClick={handleConfirmMnemonic}
                  class="w-full"
                  disabled={!mnemonicConfirmed()}
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
                <FieldLabel for="name">Name</FieldLabel>
                <Input
                  id="name"
                  type="text"
                  placeholder="John Doe"
                  value={name()}
                  onInput={(e) => setName(e.currentTarget.value)}
                  required
                  disabled={loading()}
                  autocomplete="name"
                />
              </Field>

              <Field>
                <FieldLabel for="email">Email</FieldLabel>
                <Input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  value={email()}
                  onInput={(e) => setEmail(e.currentTarget.value)}
                  required
                  disabled={loading()}
                  autocomplete="email"
                />
              </Field>

              <Field>
                <FieldLabel for="password">Password</FieldLabel>
                <Input
                  id="password"
                  type="password"
                  placeholder="--------"
                  value={password()}
                  onInput={(e) => setPassword(e.currentTarget.value)}
                  required
                  disabled={loading()}
                  autocomplete="new-password"
                />
              </Field>

              <Field>
                <FieldLabel for="confirm-password">Confirm Password</FieldLabel>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="--------"
                  value={confirmPassword()}
                  onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                  required
                  disabled={loading()}
                  autocomplete="new-password"
                />
              </Field>

              <Button type="submit" class="w-full" disabled={loading()}>
                {loading() ? (
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
