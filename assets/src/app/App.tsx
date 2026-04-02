import { QueryClientProvider } from "@tanstack/solid-query";
import { For, Show } from "solid-js";
import { PasswordReentryDialog } from "@/features/auth";
import { PendingDeviceMonitor } from "@/features/devices";
import { deviceState, tofuErrors } from "@/entities/session";
import { initializeApiClient } from "@/shared/api";
import { queryClient } from "@/shared/lib/query-client";
import { Spinner } from "@/shared/ui/spinner";
import { ThemeProvider } from "@/shared/ui/theme-provider";
import { isPublicPath, useSessionBootstrap } from "@/app/bootstrap/session";
import { AppRoutes } from "@/app/router/AppRoutes";
import "@/app.css";

export default function App() {
  initializeApiClient({
    getDeviceId: () => deviceState()?.deviceId ?? null,
  });

  const { ready, showPasswordReentry, transientError, retryRestore, closePasswordReentry } =
    useSessionBootstrap();

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
              <AppRoutes />
              <PasswordReentryDialog
                open={showPasswordReentry()}
                onComplete={closePasswordReentry}
              />
            </PendingDeviceMonitor>
          </QueryClientProvider>
        </Show>
      </Show>
    </ThemeProvider>
  );
}
