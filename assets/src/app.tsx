import { Router, Route } from "@solidjs/router";
import { createSignal, onMount, Show } from "solid-js";
import "./app.css";
import HomePage from "@/routes/home";
import LoginPage from "@/routes/auth/login";
import RegisterPage from "@/routes/auth/register";
import { restoreSession } from "@/features/auth";
import { setFullSession, setAuthState } from "@/shared/lib/auth-state";
import { Spinner } from "@/shared/ui/spinner";

export default function App() {
  const [ready, setReady] = createSignal(false);

  onMount(async () => {
    try {
      const result = await restoreSession();
      if (result) {
        const auth = {
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          umk: result.umk,
          identityKeys: result.identityKeys,
          expiresAt: result.expiresAt,
          needsPasswordReentry: result.needsPasswordReentry,
        };

        if (result.deviceId) {
          setFullSession(auth, {
            deviceId: result.deviceId,
            deviceEcdhPrivate: result.deviceEcdhPrivate,
            deviceSigningPrivate: result.deviceSigningPrivate,
          });
        } else {
          setAuthState(auth);
        }
      }
    } finally {
      setReady(true);
    }
  });

  return (
    <Show
      when={ready()}
      fallback={
        <main class="min-h-screen flex items-center justify-center">
          <Spinner class="size-6" />
        </main>
      }
    >
      <Router>
        <Route path="/" component={HomePage} />
        <Route path="/auth/login" component={LoginPage} />
        <Route path="/auth/register" component={RegisterPage} />
      </Router>
    </Show>
  );
}
