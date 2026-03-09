import { createSignal, Show, Match, Switch } from "solid-js";
import { useNavigate, useSearchParams } from "@solidjs/router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Spinner } from "@/shared/ui/spinner";
import { KeyRoundIcon, AlertTriangleIcon, CheckCircleIcon } from "lucide-solid";
import { setAuthState } from "@/shared/lib/auth-state";

type Phase = "request" | "sent" | "verifying" | "error";

export default function PasswordResetPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [phase, setPhase] = createSignal<Phase>(searchParams.token ? "verifying" : "request");
  const [email, setEmail] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  // Auto-verify if token is in URL
  const tokenParam = Array.isArray(searchParams.token) ? searchParams.token[0] : searchParams.token;
  if (tokenParam) {
    verifyToken(tokenParam);
  }

  async function verifyToken(token: string) {
    setPhase("verifying");
    try {
      const res = await fetch("/api/auth/password-reset/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
        credentials: "include",
      });

      if (!res.ok) {
        setError("Invalid or expired reset link. Please request a new one.");
        setPhase("error");
        return;
      }

      const data = await res.json();

      setAuthState({
        user: data.user,
        sessionId: data.session_id,
        umk: null,
        identityKeys: null,
        expiresAt: null,
      });

      navigate("/auth/recovery?password_reset=true");
    } catch {
      setError("Verification failed. Please try again.");
      setPhase("error");
    }
  }

  const handleRequest = async (e: Event) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/auth/password-reset/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email().trim().toLowerCase() }),
        credentials: "include",
      });

      if (res.ok) {
        setPhase("sent");
      } else {
        setError("Request failed. Please try again.");
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-md">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <KeyRoundIcon class="size-6" />
            Reset Password
          </CardTitle>
          <CardDescription>
            Enter your email to receive a password reset link.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Switch>
            <Match when={phase() === "request" || phase() === "error"}>
              <form onSubmit={handleRequest} class="space-y-4">
                <Show when={error()}>
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
                    value={email()}
                    onInput={(e) => setEmail(e.currentTarget.value)}
                    required
                    disabled={loading()}
                    autocomplete="email"
                  />
                </Field>
                <Button type="submit" class="w-full" disabled={loading()}>
                  {loading() ? (
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

            <Match when={phase() === "sent"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <CheckCircleIcon class="size-10 text-green-500" />
                <p class="text-sm text-muted-foreground text-center">
                  If an account exists with that email, we sent a password reset link.
                  Check your inbox and click the link to continue.
                </p>
                <Button variant="outline" onClick={() => navigate("/auth/login")}>
                  Back to Login
                </Button>
              </div>
            </Match>

            <Match when={phase() === "verifying"}>
              <div class="flex flex-col items-center gap-4 py-8">
                <Spinner class="size-6" />
                <p class="text-sm text-muted-foreground">
                  Verifying your reset link...
                </p>
              </div>
            </Match>
          </Switch>
        </CardContent>
      </Card>
    </main>
  );
}
