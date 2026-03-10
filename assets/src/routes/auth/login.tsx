import { createSignal, Show } from "solid-js";
import { useNavigate, A } from "@solidjs/router";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Label } from "@/shared/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Checkbox } from "@/shared/ui/checkbox";
import { Spinner } from "@/shared/ui/spinner";
import { AlertTriangleIcon } from "lucide-solid";
import { login } from "@/features/auth";
import { setFullSession, setAuthState, setTofuErrors } from "@/shared/lib/auth-state";

export default function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [rememberMe, setRememberMe] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const result = await login(email(), password(), rememberMe());

      if (result.type === "device_required") {
        setAuthState({
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          umk: null,
          identityKeys: null,
          expiresAt: null,
        });
        navigate("/devices/register");
        return;
      }

      setFullSession(
        {
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          umk: result.umk,
          identityKeys: result.identityKeys,
          expiresAt: null,
        },
        {
          deviceId: result.deviceId,
          deviceEcdhPrivate: result.deviceEcdhPrivate,
          deviceSigningPrivate: result.deviceSigningPrivate,
        },
      );

      if (result.tofuWarnings.length > 0) {
        setTofuErrors(result.tofuWarnings);
      }

      navigate("/dashboard");
    } catch (err) {
      if (err instanceof Error && err.message.includes("invalid_credentials")) {
        setError("Invalid email or password");
      } else {
        setError(err instanceof Error ? err.message : "Login failed");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-md">
        <CardHeader class="space-y-1">
          <CardTitle class="text-2xl font-bold">Login</CardTitle>
          <CardDescription>
            Enter your credentials to access your account
          </CardDescription>
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
                autocomplete="current-password"
              />
            </Field>

            <div class="flex items-center space-x-2">
              <Checkbox
                id="remember"
                checked={rememberMe()}
                onChange={(checked: boolean) => setRememberMe(checked)}
                disabled={loading()}
              />
              <Label
                for="remember"
                class="text-xs font-sans normal-case tracking-normal"
              >
                Keep me signed in
              </Label>
            </div>

            <Button type="submit" class="w-full" disabled={loading()}>
              {loading() ? (
                <span class="flex items-center gap-2">
                  <Spinner class="size-3" /> Signing in...
                </span>
              ) : (
                "Sign In"
              )}
            </Button>

            <p class="text-center text-sm text-muted-foreground">
              Don't have an account?{" "}
              <A href="/auth/register" class="text-primary hover:underline">
                Register
              </A>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
