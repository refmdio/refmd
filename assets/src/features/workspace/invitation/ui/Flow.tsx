import { onCleanup, onMount, createEffect, createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { workspacesApi } from "@/shared/api";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Spinner } from "@/shared/ui/spinner";
import {
  acceptInvitationWithKekPersistence,
  type AcceptedWorkspaceMembership,
} from "../lib/accept";
import { hasGuestRedeemMaterial } from "../lib/guest-material";
import { redeemGuestInvitation } from "../lib/guest-redeem";
import { isRetryableInvitationError } from "../lib/retry";
import { clearInvitationToken, getStoredInvitationToken, readInvitationToken } from "../lib/token";

type InvitationStatus =
  | "loading"
  | "need_auth"
  | "guest_confirm"
  | "confirm"
  | "accepting"
  | "guest_accepting"
  | "success"
  | "partial"
  | "error";

export function WorkspaceInvitationFlow() {
  const navigate = useNavigate();
  const [status, setStatus] = createSignal<InvitationStatus>("loading");
  const [invitationKind, setInvitationKind] = createSignal<"member" | "guest" | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [retryable, setRetryable] = createSignal(false);
  const [retryMode, setRetryMode] = createSignal<"accept" | "guest" | null>(null);
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

  const runGuestRedeem = async (): Promise<void> => {
    const token = getStoredInvitationToken();
    if (!token) {
      setError("No invitation token found.");
      setStatus("error");
      return;
    }

    setError(null);
    setRetryable(false);
    setRetryMode("guest");
    setKekWarning(null);
    setStatus("guest_accepting");

    try {
      const result = await redeemGuestInvitation(token);
      setMembership({
        workspaceId: result.workspace_id,
        workspaceName: result.workspace_name,
        roleName: "Guest",
      });
      clearInvitationToken();
      setStatus("success");
    } catch (guestError) {
      setError(guestError instanceof Error ? guestError.message : "Failed to join as guest");
      setRetryable(isRetryableInvitationError(guestError));
      setStatus("error");
    }
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
    setRetryMode("accept");
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
      setRetryable(isRetryableInvitationError(acceptError));
      setStatus("error");
    }
  };

  onMount(() => {
    void initializeInvitation();
  });

  const initializeInvitation = async (): Promise<void> => {
    const token = readInvitationToken();
    if (!token) {
      setError("No invitation token found.");
      setStatus("error");
      return;
    }

    let kind: "member" | "guest";
    try {
      kind = (await workspacesApi.lookupInvitation(token)).kind;
      setInvitationKind(kind);
    } catch (lookupError) {
      setError(lookupError instanceof Error ? lookupError.message : "Invitation not found.");
      setStatus("error");
      return;
    }

    const auth = authState();
    if (!auth) {
      setStatus(kind === "guest" ? "guest_confirm" : "need_auth");
      return;
    }

    if (auth.user.accountType === "guest") {
      if (kind !== "guest") {
        setError("Sign in with an account to accept this invitation.");
        setStatus("error");
        return;
      }

      void (async () => {
        try {
          const hasMaterial = await hasGuestRedeemMaterial(token);
          if (hasMaterial) {
            void runGuestRedeem();
            return;
          }
          setError("Guest access is not available on this device.");
          setStatus("error");
        } catch (materialError) {
          setError(
            materialError instanceof Error
              ? materialError.message
              : "Failed to read guest access material.",
          );
          setRetryable(true);
          setStatus("error");
        }
      })();
      return;
    }

    if (kind === "guest") {
      setError("Sign out before joining as a guest.");
      setStatus("error");
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
  };

  onCleanup(() => {
    if (redirectTimer) clearTimeout(redirectTimer);
  });

  createEffect(() => {
    const currentStatus = status();
    if (currentStatus !== "loading" && currentStatus !== "need_auth") return;

    const auth = authState();
    const device = deviceState();
    if (invitationKind() !== "member") return;
    if (!auth || !device || !cryptoWorkerReady()) return;
    if (auth.user.accountType === "guest") return;

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
              Someone invited your account to collaborate on a workspace. Create an account or sign
              in to accept.
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

      <Show when={status() === "guest_confirm"}>
        <Card class="w-full max-w-md">
          <CardHeader class="space-y-1 text-center">
            <CardTitle class="text-2xl font-bold">Join as Guest</CardTitle>
            <CardDescription>
              This invitation lets you join the workspace as an account-less guest on this device.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <Button class="w-full" onClick={() => void runGuestRedeem()}>
              Continue as Guest
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

      <Show
        when={status() === "loading" || status() === "accepting" || status() === "guest_accepting"}
      >
        <div class="w-full max-w-sm space-y-4 text-center">
          <Spinner class="size-8 mx-auto" />
          <p class="text-muted-foreground">
            {status() === "loading"
              ? "Processing invitation..."
              : status() === "guest_accepting"
                ? "Joining as guest..."
                : "Accepting invitation..."}
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
              <Button
                onClick={() =>
                  retryMode() === "guest"
                    ? void runGuestRedeem()
                    : void runAcceptance("Retry failed")
                }
              >
                Retry
              </Button>
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
