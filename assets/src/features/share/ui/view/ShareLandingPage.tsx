import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import type { ShareLandingRoot } from "../../lib/route/landing";
import { resolveShareLandingRoute } from "../../lib/route/landing";
import {
  bootstrapPasswordProtectedShareParticipantSession,
  bootstrapShareParticipantSession,
  prewarmShareParticipantKeypair,
} from "../../lib/session/session";
import {
  preloadShareDocumentRoute,
  preloadShareDocumentRouteFromBootstrap,
} from "../../lib/route/document";
import { enterShareRouteSession, leaveShareRouteSession } from "../../lib/route/session";
import {
  readShareUrlFragmentFromLocation,
  readWorkspacePinBootstrapHashFromLocation,
} from "@/entities/mount";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { ApiError, getRateLimitRetryMs } from "@/shared/api";
import { Button } from "@/shared/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

function isDocumentRoot(root: ShareLandingRoot): root is { document_token: string } {
  return typeof root.document_token === "string";
}

function isFolderRoot(root: ShareLandingRoot): root is { folder_token: string } {
  return typeof root.folder_token === "string";
}

type PageState = "loading" | "password" | "error";

function preloadDocumentEditorModule(): void {
  void import("@/widgets/document-editor").catch(() => {});
}

function preloadShareDocumentPageModule(): void {
  void import("@/pages/share/d/[documentToken]").catch(() => {});
}

function preloadDocumentSyncBootstrapModule(): void {
  void import("@/features/editor/lib/sync/bootstrap-initialize").catch(() => {});
}

function preloadDocumentShareOpen(
  documentToken: string,
  shareSlug: string,
  rootDocumentBootstrap?: unknown,
): void {
  preloadShareDocumentPageModule();
  preloadDocumentEditorModule();
  preloadDocumentSyncBootstrapModule();
  if (
    rootDocumentBootstrap &&
    typeof rootDocumentBootstrap === "object" &&
    !Array.isArray(rootDocumentBootstrap)
  ) {
    void preloadShareDocumentRouteFromBootstrap(
      documentToken,
      shareSlug,
      rootDocumentBootstrap as Record<string, unknown>,
    ).catch(() => {});
    return;
  }
  void preloadShareDocumentRoute(documentToken, shareSlug).catch(() => {});
}

function hasDirectShareBootstrapMaterial(): boolean {
  return Boolean(readShareUrlFragmentFromLocation() && readWorkspacePinBootstrapHashFromLocation());
}

function shareLandingErrorCode(error: unknown): string | null {
  if (error instanceof ApiError) return error.code;
  return error instanceof Error && error.message ? error.message : null;
}

function shareLandingErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) return "Share not found.";
  const code = shareLandingErrorCode(error);
  if (
    code === "share_capability_secret_required" ||
    code === "workspace_pin_bootstrap_hash_required" ||
    code === "share_session_required"
  ) {
    return "Invalid share link.";
  }
  return "Unable to verify share link.";
}

export function ShareLandingPage() {
  const navigate = useNavigate();
  const params = useParams<{ shareSlug?: string }>();
  const [error, setError] = createSignal<string | null>(null);
  const [password, setPassword] = createSignal("");
  const [pageState, setPageState] = createSignal<PageState>("loading");
  const [submittingPassword, setSubmittingPassword] = createSignal(false);
  let pageActive = true;
  let requestVersion = 0;
  let pendingShareSlug: string | null = null;
  let resolvedShareSlug: string | null = null;

  enterShareRouteSession();
  onCleanup(() => {
    pageActive = false;
    leaveShareRouteSession();
  });

  async function navigateToCanonical(root: ShareLandingRoot, isActive: () => boolean) {
    if (!isActive()) return;
    const shareSlug = params.shareSlug;
    const hash = shareSlug ? canonicalShareHash(shareSlug) : "";
    if (isDocumentRoot(root)) {
      navigate(`/share/d/${root.document_token}${hash}`, { replace: true, scroll: false });
      return;
    }

    if (isFolderRoot(root)) {
      navigate(`/share/f/${root.folder_token}${hash}`, { replace: true, scroll: false });
      return;
    }

    throw new Error("unsupported_share_root");
  }

  async function handleBootstrap(shareSlug: string, isActive: () => boolean) {
    const hasDirectBootstrapMaterial = hasDirectShareBootstrapMaterial();
    if (hasDirectBootstrapMaterial) {
      void prewarmShareParticipantKeypair(shareSlug).catch(() => {});
    }

    const resolution = await resolveShareLandingRoute(shareSlug, {
      preferBootstrap: hasDirectBootstrapMaterial,
    });
    if (!isActive()) return;

    switch (resolution.kind) {
      case "ready":
        if (isDocumentRoot(resolution.root)) {
          preloadDocumentShareOpen(resolution.root.document_token, shareSlug);
        }
        await navigateToCanonical(resolution.root, isActive);
        return;

      case "password-required":
        setPageState("password");
        return;

      case "bootstrap": {
        const root = resolution.landing.root;
        let navigatedFromActiveSession = false;
        if (root && isDocumentRoot(root)) {
          preloadShareDocumentPageModule();
          preloadDocumentEditorModule();
          preloadDocumentSyncBootstrapModule();
        }
        const { bootstrap } = await bootstrapShareParticipantSession(shareSlug, {
          landing: resolution.landing,
          onActiveSessionReady: ({ bootstrap: activeBootstrap }) => {
            if (isDocumentRoot(activeBootstrap.root)) {
              preloadDocumentShareOpen(
                activeBootstrap.root.document_token,
                shareSlug,
                activeBootstrap.root_document_bootstrap,
              );
            }
            if (isActive()) {
              navigatedFromActiveSession = true;
              void navigateToCanonical(activeBootstrap.root, isActive);
            }
          },
        });
        if (!isActive() || navigatedFromActiveSession) return;
        if (isDocumentRoot(bootstrap.root)) {
          preloadDocumentShareOpen(
            bootstrap.root.document_token,
            shareSlug,
            bootstrap.root_document_bootstrap,
          );
        }
        await navigateToCanonical(bootstrap.root, isActive);
        return;
      }
    }
  }

  const handlePasswordSubmit = async (event: Event) => {
    event.preventDefault();
    const shareSlug = params.shareSlug;
    const isActive = () => pageActive && params.shareSlug === shareSlug;

    if (!shareSlug) {
      setError("Invalid share link.");
      setPageState("error");
      return;
    }

    setError(null);
    setSubmittingPassword(true);

    try {
      const { bootstrap } = await bootstrapPasswordProtectedShareParticipantSession(
        shareSlug,
        password(),
      );
      if (!isActive()) return;

      if (isDocumentRoot(bootstrap.root)) {
        preloadDocumentShareOpen(bootstrap.root.document_token, shareSlug);
      }
      await navigateToCanonical(bootstrap.root, isActive);
    } catch (err) {
      if (isActive()) {
        const retryMs = getRateLimitRetryMs(err);
        setError(
          retryMs
            ? `Too many attempts. Try again in ${Math.ceil(retryMs / 1000)} seconds.`
            : "Share not found or password is invalid.",
        );
        setPageState("password");
      }
    } finally {
      if (isActive()) {
        setSubmittingPassword(false);
      }
    }
  };

  createEffect(() => {
    const shareSlug = params.shareSlug;
    if (!shareSlug) {
      requestVersion += 1;
      pendingShareSlug = null;
      resolvedShareSlug = null;
      setError("Invalid share link.");
      setPassword("");
      setPageState("error");
      return;
    }

    if (pendingShareSlug === shareSlug || resolvedShareSlug === shareSlug) return;

    const currentRequest = ++requestVersion;
    pendingShareSlug = shareSlug;
    setError(null);
    setPassword("");
    setPageState("loading");

    const isActive = () =>
      pageActive && currentRequest === requestVersion && params.shareSlug === shareSlug;

    void (async () => {
      try {
        pendingShareSlug = null;
        resolvedShareSlug = shareSlug;
        await handleBootstrap(shareSlug, isActive);
      } catch (error) {
        if (isActive()) {
          pendingShareSlug = null;
          resolvedShareSlug = null;
          setError(shareLandingErrorMessage(error));
          setPageState("error");
        }
      }
    })();
  });

  return (
    <main class="min-h-screen flex items-center justify-center p-6">
      <Show
        when={pageState() === "password"}
        fallback={
          pageState() === "error" ? (
            <div class="text-sm text-muted-foreground">{error()}</div>
          ) : (
            <Spinner class="size-6" />
          )
        }
      >
        <div class="w-full max-w-md border border-border/60 bg-background/60 p-8 shadow-[var(--glass-shadow-outline)] backdrop-blur">
          <div class="space-y-2">
            <p class="font-mono text-[10px] uppercase tracking-[0.32em] text-muted-foreground">
              Protected Share
            </p>
            <h1 class="text-xl font-semibold text-foreground">Enter password to continue</h1>
            <p class="text-sm leading-relaxed text-muted-foreground">
              Your participant session will be created after password verification succeeds.
            </p>
          </div>

          <form class="mt-6 space-y-4" onSubmit={handlePasswordSubmit}>
            <Show when={error()}>
              {(message) => (
                <Alert variant="destructive">
                  <AlertDescription>{message()}</AlertDescription>
                </Alert>
              )}
            </Show>

            <Field>
              <FieldLabel for="share-password">Password</FieldLabel>
              <Input
                id="share-password"
                type="password"
                value={password()}
                onInput={(event) => setPassword(event.currentTarget.value)}
                autocomplete="current-password"
                placeholder="--------"
                required
                disabled={submittingPassword()}
              />
              <FieldDescription>
                Use the password that was set when this share was created.
              </FieldDescription>
            </Field>

            <Button
              type="submit"
              class="w-full"
              disabled={submittingPassword() || password().length === 0}
            >
              {submittingPassword() ? (
                <span class="flex items-center gap-2">
                  <Spinner class="size-3" /> Unlocking...
                </span>
              ) : (
                "Unlock Share"
              )}
            </Button>
          </form>
        </div>
      </Show>
    </main>
  );
}

function canonicalShareHash(shareSlug: string): string {
  const params = new URLSearchParams();
  params.set("s", shareSlug);
  return `#${params.toString()}`;
}
