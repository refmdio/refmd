import { QueryClientProvider } from "@tanstack/solid-query";
import { createEffect, For, Show } from "solid-js";
import { PasswordReentryDialog } from "@/features/auth";
import { PendingDeviceMonitor } from "@/features/devices";
import { authState, clearSession, deviceState, tofuErrors } from "@/entities/session";
import { initializeApiClient } from "@/shared/api";
import { queryClient } from "@/shared/lib/query/client";
import { resetPhoenixSocketState } from "@/shared/lib/ws/socket";
import { Spinner } from "@/shared/ui/spinner";
import { ThemeProvider } from "@/shared/ui/theme-provider";
import { isPublicPath, useSessionBootstrap } from "@/app/bootstrap/session";
import { AppRoutes } from "@/app/router/AppRoutes";
import "@/app.css";

type SessionValidationResult =
  | { status: "active"; sessionId: string | null }
  | { status: "unauthenticated" }
  | { status: "unknown" };

let pendingUserUnauthorizedValidation: Promise<void> | null = null;
let lastActiveSessionValidation: { sessionId: string; at: number } | null = null;
let observedSessionId: string | null = null;
let lastSessionActivation: { sessionId: string; at: number } | null = null;

async function fetchCurrentSessionState(): Promise<SessionValidationResult> {
  try {
    const response = await fetch("/api/auth/me", {
      credentials: "include",
      cache: "no-store",
      headers: {
        Accept: "application/json",
      },
    });

    if (response.status === 401 || response.status === 403) {
      return { status: "unauthenticated" };
    }

    if (!response.ok) return { status: "unknown" };

    const body = (await response.json().catch(() => null)) as { session_id?: unknown } | null;
    return {
      status: "active",
      sessionId: typeof body?.session_id === "string" ? body.session_id : null,
    };
  } catch {
    return { status: "unknown" };
  }
}

function validateUserUnauthorizedBeforeClearing(sessionIdAtUnauthorized: string): void {
  if (
    lastSessionActivation?.sessionId === sessionIdAtUnauthorized &&
    Date.now() - lastSessionActivation.at < 60_000
  ) {
    return;
  }
  if (
    lastActiveSessionValidation?.sessionId === sessionIdAtUnauthorized &&
    Date.now() - lastActiveSessionValidation.at < 15_000
  ) {
    return;
  }
  if (pendingUserUnauthorizedValidation) return;

  pendingUserUnauthorizedValidation = (async () => {
    await new Promise((resolve) => setTimeout(resolve, 750));
    const result = await fetchCurrentSessionState();
    const currentSessionId = authState()?.sessionId;

    if (!currentSessionId || currentSessionId !== sessionIdAtUnauthorized) return;
    if (result.status === "unknown") return;
    if (result.status === "active") {
      lastActiveSessionValidation = { sessionId: sessionIdAtUnauthorized, at: Date.now() };
      return;
    }

    clearSession();
    resetPhoenixSocketState();
    queryClient.clear();
  })().finally(() => {
    pendingUserUnauthorizedValidation = null;
  });
}

export default function App() {
  createEffect(() => {
    const sessionId = authState()?.sessionId ?? null;
    if (sessionId && sessionId !== observedSessionId) {
      lastSessionActivation = { sessionId, at: Date.now() };
    }
    observedSessionId = sessionId;
  });

  initializeApiClient({
    getDeviceId: () => deviceState()?.deviceId ?? null,
    onUnauthorized: (scope) => {
      if (scope !== "user") {
        resetPhoenixSocketState();
        return;
      }

      const sessionId = authState()?.sessionId;
      if (!sessionId) return;
      validateUserUnauthorizedBeforeClearing(sessionId);
    },
  });

  const { ready, showPasswordReentry, transientError, retryRestore, closePasswordReentry } =
    useSessionBootstrap();
  const shouldBlockForPasswordReentry = () => showPasswordReentry() && !isPublicPath();

  return (
    <ThemeProvider defaultTheme="system" enableSystem attribute="class">
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
                  void retryRestore();
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
                <For each={tofuErrors()}>
                  {(entry) => <li class="text-destructive">{entry}</li>}
                </For>
              </ul>
            </div>
          </main>
        </Show>
        <Show when={tofuErrors().length === 0 && (!transientError() || isPublicPath())}>
          <QueryClientProvider client={queryClient}>
            <PendingDeviceMonitor>
              <Show when={!shouldBlockForPasswordReentry()}>
                <AppRoutes />
              </Show>
              <PasswordReentryDialog
                open={shouldBlockForPasswordReentry()}
                onComplete={closePasswordReentry}
              />
            </PendingDeviceMonitor>
          </QueryClientProvider>
        </Show>
      </Show>
    </ThemeProvider>
  );
}
