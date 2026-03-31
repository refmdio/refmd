import { Router, Route } from "@solidjs/router";
import { createSignal, onMount, Show, For } from "solid-js";
import { QueryClientProvider } from "@tanstack/solid-query";
import "./app.css";
import { Navigate } from "@solidjs/router";
import DashboardPage from "@/routes/dashboard";
import LoginPage from "@/routes/auth/login";
import RegisterPage from "@/routes/auth/register";
import DeviceRegisterPage from "@/routes/devices/register";
import RecoveryPage from "@/routes/auth/recovery";
import PasswordResetPage from "@/routes/auth/password-reset";
import InvitePage from "@/routes/invite";
import { PasswordReentryDialog, restoreSession, restoreOfflineSession } from "@/features/auth";
import { PendingDeviceMonitor } from "@/features/devices";
import {
  setFullSession,
  setAuthState,
  setDeviceState,
  tofuErrors,
  setTofuErrors,
  setCryptoWorkerReady,
} from "@/shared/lib/auth-state";
import { Spinner } from "@/shared/ui/spinner";
import { AppShell } from "./app-shell";

import { queryClient } from "@/shared/lib/query-client";

function isPublicPath(): boolean {
  const path = window.location.pathname;
  return path.startsWith("/auth/") || path === "/devices/register" || path.startsWith("/invite");
}

export default function App() {
  const [ready, setReady] = createSignal(false);
  const [showPasswordReentry, setShowPasswordReentry] = createSignal(false);
  const [transientError, setTransientError] = createSignal<string | null>(null);

  const attemptRestore = async () => {
    setTransientError(null);
    try {
      const result = await restoreSession();
      if (result === "rate_limited") {
        setTransientError("Too many requests. Please wait a moment and try again.");
        return;
      }
      if (result === "transient_error") {
        const offlineResult = await restoreOfflineSession();
        if (offlineResult) {
          setAuthState({
            user: {
              id: offlineResult.userId,
              email: offlineResult.email,
              name: offlineResult.name,
            },
            sessionId: "",
            identitySigningPublic: null,
            identityEcdhPublic: null,
            expiresAt: "",
          });
          setDeviceState({
            deviceId: offlineResult.deviceId,
            deviceSigningPublic: offlineResult.deviceSigningPublic,
            deviceEcdhPublic: offlineResult.deviceEcdhPublic,
          });
          // DSK is set even if !workerReady (no UMK). Offline operations
          // (unwrapDekFromOffline, decryptOfflineCache) only need DSK.
          setCryptoWorkerReady(true);
        } else {
          setTransientError(
            "Could not connect to the server. Please check your connection and try again.",
          );
        }
        return;
      }
      // null = no valid session (401/403/no cookie). Try offline if network is down.
      if (!result) {
        const { offlineMode } = await import("@/shared/lib/offline/offline-state");
        if (offlineMode()) {
          const offlineResult = await restoreOfflineSession();
          if (offlineResult) {
            setAuthState({
              user: {
                id: offlineResult.userId,
                email: offlineResult.email,
                name: offlineResult.name,
              },
              sessionId: "",
              identitySigningPublic: null,
              identityEcdhPublic: null,
              expiresAt: "",
            });
            setDeviceState({
              deviceId: offlineResult.deviceId,
              deviceSigningPublic: offlineResult.deviceSigningPublic,
              deviceEcdhPublic: offlineResult.deviceEcdhPublic,
            });
            setCryptoWorkerReady(true);
            return;
          }
        }
        // No offline fallback available — stay on login page
        return;
      }
      if (result) {
        const auth = {
          user: { id: result.userId, email: result.email, name: result.name },
          sessionId: result.sessionId,
          identitySigningPublic: result.identitySigningPublic,
          identityEcdhPublic: result.identityEcdhPublic,
          expiresAt: result.expiresAt,
          needsPasswordReentry: result.needsPasswordReentry,
        };

        if (result.deviceId && result.deviceSigningPublic) {
          setFullSession(auth, {
            deviceId: result.deviceId,
            deviceSigningPublic: result.deviceSigningPublic,
            deviceEcdhPublic: result.deviceEcdhPublic,
          });
        } else {
          setAuthState(auth);
          if (result.deviceId) {
            setDeviceState({
              deviceId: result.deviceId,
              deviceSigningPublic: null,
              deviceEcdhPublic: null,
            });
          }
        }

        if (result.workerReady) {
          setCryptoWorkerReady(true);
        }

        if (result.tofuWarnings.length > 0) {
          setTofuErrors(result.tofuWarnings);
        }

        if (result.needsPasswordReentry) {
          setShowPasswordReentry(true);
        }

        if (!result.deviceVerified && !result.needsPasswordReentry) {
          const path = window.location.pathname;
          const isPublicPath2 =
            path.startsWith("/auth/") || path === "/devices/register" || path.startsWith("/invite");
          if (!isPublicPath2) {
            window.location.replace("/devices/register");
            return;
          }
        }
      }
    } catch (e) {
      if (
        e instanceof Error &&
        (("code" in e && (e as any).code === "tofu_hard_fail") || e.message.includes("TOFU"))
      ) {
        setTofuErrors([e.message]);
      } else {
        setTransientError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setReady(true);
    }
  };

  onMount(attemptRestore);

  return (
    <Show
      when={ready()}
      fallback={
        <main class="min-h-screen flex items-center justify-center">
          <Spinner class="size-6" />
        </main>
      }
    >
      <Show when={transientError() && !isPublicPath()}>
        <main class="min-h-screen flex items-center justify-center p-6">
          <div class="max-w-md w-full space-y-4 text-center">
            <h1 class="text-xl font-semibold">Temporarily Unavailable</h1>
            <p class="text-muted-foreground">{transientError()}</p>
            <button
              class="px-4 py-2 bg-foreground text-background text-sm hover:bg-foreground/90 transition-colors"
              onClick={() => {
                setReady(false);
                attemptRestore();
              }}
            >
              Try Again
            </button>
          </div>
        </main>
      </Show>
      <Show when={!transientError() && tofuErrors().length > 0}>
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
      <Show when={tofuErrors().length === 0 && (!transientError() || isPublicPath())}>
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
                <Route path={["/dashboard", "/document/:documentId"]} component={DashboardPage} />
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
