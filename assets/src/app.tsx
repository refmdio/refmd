import { Router, Route } from "@solidjs/router";
import { createSignal, onMount, Show, For } from "solid-js";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import "./app.css";
import { Navigate } from "@solidjs/router";
import DashboardPage from "@/routes/dashboard";
import LoginPage from "@/routes/auth/login";
import RegisterPage from "@/routes/auth/register";
import DeviceRegisterPage from "@/routes/devices/register";
import RecoveryPage from "@/routes/auth/recovery";
import PasswordResetPage from "@/routes/auth/password-reset";
import InvitePage from "@/routes/invite";
import { PasswordReentryDialog, restoreSession } from "@/features/auth";
import { PendingDeviceMonitor } from "@/features/devices";
import {
  setFullSession,
  setAuthState,
  setDeviceState,
  tofuErrors,
  setTofuErrors,
} from "@/shared/lib/auth-state";
import { TofuHardFailError } from "@/shared/lib/crypto";
import { Spinner } from "@/shared/ui/spinner";
import { AppShell } from "./app-shell";

const queryClient = new QueryClient();

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
          if (result.deviceId) {
            setDeviceState({
              deviceId: result.deviceId,
              deviceEcdhPrivate: null,
              deviceSigningPrivate: null,
            });
          }
        }

        if (result.tofuWarnings.length > 0) {
          setTofuErrors(result.tofuWarnings);
        }

        if (result.needsPasswordReentry) {
          setShowPasswordReentry(true);
        }

        if (!result.deviceVerified && !result.needsPasswordReentry) {
          const path = window.location.pathname;
          const isPublicPath =
            path.startsWith("/auth/") || path === "/devices/register" || path.startsWith("/invite");
          if (!isPublicPath) {
            window.location.replace("/devices/register");
            return;
          }
        }
      }
    } catch (e) {
      if (e instanceof TofuHardFailError) {
        setTofuErrors([e.message]);
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
      <Show when={tofuErrors().length > 0}>
        <main class="min-h-screen flex items-center justify-center p-6">
          <div class="max-w-md w-full space-y-4 text-center">
            <h1 class="text-xl font-bold text-destructive">Key Verification Failed</h1>
            <p class="text-muted-foreground">
              Device key integrity check failed. Operations are blocked for security.
            </p>
            <ul class="text-sm text-left space-y-1">
              <For each={tofuErrors()}>{(e) => <li class="text-destructive">{e}</li>}</For>
            </ul>
          </div>
        </main>
      </Show>
      <Show when={tofuErrors().length === 0}>
        <QueryClientProvider client={queryClient}>
          <PendingDeviceMonitor>
            <Router>
              {/* Public routes */}
              <Route path="/auth/login" component={LoginPage} />
              <Route path="/auth/register" component={RegisterPage} />
              <Route path="/auth/recovery" component={RecoveryPage} />
              <Route path="/auth/password-reset" component={PasswordResetPage} />
              <Route path="/devices/register" component={DeviceRegisterPage} />
              <Route path="/invite" component={InvitePage} />

              {/* Authenticated routes with layout */}
              <Route path="/" component={AppShell}>
                <Route path="/" component={() => <Navigate href="/dashboard" />} />
                <Route path="/dashboard" component={DashboardPage} />
              </Route>
            </Router>
            <PasswordReentryDialog
              open={showPasswordReentry()}
              onComplete={() => setShowPasswordReentry(false)}
            />
          </PendingDeviceMonitor>
        </QueryClientProvider>
      </Show>
    </Show>
  );
}
