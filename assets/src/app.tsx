import { Router, Route } from "@solidjs/router";
import { createSignal, onMount, Show } from "solid-js";
import "./app.css";
import HomePage from "@/routes/home";
import LoginPage from "@/routes/auth/login";
import RegisterPage from "@/routes/auth/register";
import DevicesPage from "@/routes/devices";
import DeviceRegisterPage from "@/routes/auth/device-register";
import RecoveryPage from "@/routes/auth/recovery";
import PasswordResetPage from "@/routes/auth/password-reset";
import PasswordReentryDialog from "@/features/auth/password-reentry-dialog";
import { PendingDeviceMonitor } from "@/features/devices/pending-device-monitor";
import { restoreSession } from "@/features/auth";
import { setFullSession, setAuthState } from "@/shared/lib/auth-state";
import { Spinner } from "@/shared/ui/spinner";

export default function App() {
  const [ready, setReady] = createSignal(false);
  const [showPasswordReentry, setShowPasswordReentry] = createSignal(false);

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

        if (result.deviceId && result.deviceSigningPrivate) {
          setFullSession(auth, {
            deviceId: result.deviceId,
            deviceEcdhPrivate: result.deviceEcdhPrivate,
            deviceSigningPrivate: result.deviceSigningPrivate,
          });
        } else {
          setAuthState(auth);
        }

        if (result.needsPasswordReentry) {
          setShowPasswordReentry(true);
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
      <PendingDeviceMonitor>
        <Router>
          <Route path="/" component={HomePage} />
          <Route path="/auth/login" component={LoginPage} />
          <Route path="/auth/register" component={RegisterPage} />
          <Route path="/auth/device-register" component={DeviceRegisterPage} />
          <Route path="/auth/recovery" component={RecoveryPage} />
          <Route path="/auth/password-reset" component={PasswordResetPage} />
          <Route path="/devices" component={DevicesPage} />
        </Router>
        <PasswordReentryDialog
          open={showPasswordReentry()}
          onComplete={() => setShowPasswordReentry(false)}
        />
      </PendingDeviceMonitor>
    </Show>
  );
}
