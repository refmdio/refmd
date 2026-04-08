import { onCleanup, onMount, createEffect, createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { ApiError } from "@/shared/api";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Spinner } from "@/shared/ui/spinner";
import {
  acceptInvitationWithKekPersistence,
  type AcceptedWorkspaceMembership,
} from "../lib/accept";
import { clearInvitationToken, getStoredInvitationToken, readInvitationToken } from "../lib/token";

type InvitationStatus =
  | "loading"
  | "need_auth"
  | "confirm"
  | "accepting"
  | "success"
  | "partial"
  | "error";

export function WorkspaceInvitationFlow() {
  const navigate = useNavigate();
  const [status, setStatus] = createSignal<InvitationStatus>("loading");
  const [error, setError] = createSignal<string | null>(null);
  const [retryable, setRetryable] = createSignal(false);
  const [kekWarning, setKekWarning] = createSignal<string | null>(null);
  const [membership, setMembership] = createSignal<AcceptedWorkspaceMembership | null>(null);
  let redirectTimer: ReturnType<typeof setTimeout> | undefined;

  const queryClient = useQueryClient();
  const navigateToWorkspace = () => {
    const currentMembership = membership();
    if (currentMembership?.workspaceId) {
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      setCurrentWorkspaceId(currentMembership.workspaceId);
    }
    navigate("/dashboard");
  };

  const runAcceptance = async (retryErrorLabel: string): Promise<void> => {
    const token = getStoredInvitationToken();
    const auth = authState();
    const device = deviceState();
    if (!token || !auth || !device || !cryptoWorkerReady()) {
      setError("Session is not ready. Please log in and try again.");
      setStatus("error");
      return;
    }

    setError(null);
    setRetryable(false);
    setKekWarning(null);
    setStatus("accepting");

    try {
      const outcome = await acceptInvitationWithKekPersistence({ token, auth, device });
      setMembership(outcome.membership);

      if (outcome.status === "success") {
        clearInvitationToken();
        setStatus("success");
        return;
      }

      setKekWarning(outcome.warning);
      setStatus("partial");
    } catch (acceptError) {
      setError(acceptError instanceof Error ? acceptError.message : retryErrorLabel);
      if (acceptError instanceof ApiError) {
        setRetryable(acceptError.status >= 500);
      } else {
        setRetryable(true);
      }
      setStatus("error");
    }
  };

  onMount(() => {
    const token = readInvitationToken();
    if (!token) {
      setError("No invitation token found.");
      setStatus("error");
      return;
    }

    const auth = authState();
    if (!auth) {
      setStatus("need_auth");
      return;
    }

    const device = deviceState();
    if (!device) {
      navigate("/devices/register");
      return;
    }

    if (!cryptoWorkerReady()) {
      if (auth.needsPasswordReentry) return;
      navigate("/devices/register");
      return;
    }

    setStatus("confirm");
  });

  onCleanup(() => {
    if (redirectTimer) clearTimeout(redirectTimer);
  });

  createEffect(() => {
    const currentStatus = status();
    if (currentStatus !== "loading" && currentStatus !== "need_auth") return;

    const auth = authState();
    const device = deviceState();
    if (!auth || !device || !cryptoWorkerReady()) return;

    setStatus("confirm");
  });

  createEffect(() => {
    if (status() !== "success") return;
    redirectTimer = setTimeout(navigateToWorkspace, 2000);
  });

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Show when={status() === "need_auth"}>
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1 text-center">
            <CardTitle class="text-2xl font-bold">You've been invited</CardTitle>
            <CardDescription>
              Someone invited you to collaborate on a workspace. Create an account or sign in to
              accept.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <Button class="w-full" onClick={() => navigate("/auth/register")}>
              Create Account
            </Button>
            <Button variant="outline" class="w-full" onClick={() => navigate("/auth/login")}>
              Sign In
            </Button>
          </CardContent>
        </Card>
      </Show>

      <Show when={status() === "confirm"}>
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1 text-center">
            <CardTitle class="text-2xl font-bold">Accept Invitation</CardTitle>
            <CardDescription>
              Accept this workspace invitation as{" "}
              <span class="font-medium text-foreground">{authState()?.user.email}</span>?
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <Button
              class="w-full"
              onClick={() => void runAcceptance("Failed to accept invitation")}
            >
              Accept Invitation
            </Button>
            <Button
              variant="outline"
              class="w-full"
              onClick={() => {
                clearInvitationToken();
                navigate("/dashboard");
              }}
            >
              Decline
            </Button>
          </CardContent>
        </Card>
      </Show>

      <Show when={status() === "loading" || status() === "accepting"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <Spinner class="size-8 mx-auto" />
          <p class="text-muted-foreground">
            {status() === "loading" ? "Processing invitation..." : "Accepting invitation..."}
          </p>
        </div>
      </Show>

      <Show when={status() === "success"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <p class="text-foreground font-medium">You've joined the workspace!</p>
          <Show when={membership()}>
            {(acceptedMembership) => (
              <p class="text-muted-foreground">
                <span class="font-medium text-foreground">
                  {acceptedMembership().workspaceName}
                </span>
                <Show when={acceptedMembership().roleName}>
                  {(role) => (
                    <span>
                      {" "}
                      as <span class="font-medium text-foreground">{role()}</span>
                    </span>
                  )}
                </Show>
              </p>
            )}
          </Show>
          <p class="text-sm text-muted-foreground">Redirecting to workspace...</p>
          <Button variant="outline" class="w-full" onClick={navigateToWorkspace}>
            Go to Workspace
          </Button>
        </div>
      </Show>

      <Show when={status() === "partial"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <p class="text-foreground font-medium">Key Setup Incomplete</p>
          <p class="text-sm text-muted-foreground">{kekWarning()}</p>
          <div class="flex gap-2 justify-center">
            <Button onClick={() => void runAcceptance("Retry failed")}>Retry</Button>
            <Button variant="outline" onClick={() => navigate("/dashboard")}>
              Go to Dashboard
            </Button>
          </div>
        </div>
      </Show>

      <Show when={status() === "error"}>
        <div class="w-full max-w-sm space-y-4 text-center">
          <p class="text-destructive font-medium">{error()}</p>
          <div class="flex gap-2 justify-center">
            <Show when={retryable()}>
              <Button onClick={() => void runAcceptance("Retry failed")}>Retry</Button>
            </Show>
            <Button
              variant="outline"
              onClick={() => {
                clearInvitationToken();
                navigate("/dashboard");
              }}
            >
              Go to Dashboard
            </Button>
          </div>
        </div>
      </Show>
    </main>
  );
}
