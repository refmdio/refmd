import { createEffect, createSignal, Show, untrack, type JSX } from "solid-js";
import { useParams, useSearchParams } from "@solidjs/router";
import {
  loadMountTrustAnchor,
  type ShareMountDocument,
  type ShareMountDetail,
} from "@/entities/mount";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { currentWorkspaceId, setCurrentWorkspaceId } from "@/entities/workspace";
import { activateSharedDocumentRoute } from "@/features/editor";
import { createMountedShareDocumentPanelTarget, usePanelWorkspace } from "@/features/panel";
import {
  getShareMountForRoute,
  openMountedShareDocument,
  respondShareMountPasswordChallenge,
} from "@/features/share";
import { getRateLimitRetryMs } from "@/shared/api";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

export function MountedShareWorkspace(props: { fallback: JSX.Element }) {
  const params = useParams<{ mountId?: string }>();
  const [searchParams] = useSearchParams();
  const workspace = usePanelWorkspace();
  const [pendingRouteKey, setPendingRouteKey] = createSignal<string | null>(null);
  const [lockedDetail, setLockedDetail] = createSignal<ShareMountDetail | null>(null);
  const [routeError, setRouteError] = createSignal<string | null>(null);
  const [password, setPassword] = createSignal("");
  const [passwordError, setPasswordError] = createSignal<string | null>(null);
  const [submittingPassword, setSubmittingPassword] = createSignal(false);
  let requestVersion = 0;

  const routeMountId = () => {
    const id = params.mountId;
    return typeof id === "string" && id.length > 0 ? id : null;
  };

  const routeShareId = () => {
    const id = searchParams.share;
    return typeof id === "string" && id.length > 0 ? id : null;
  };

  const openDocument = async (detail: ShareMountDetail, document: ShareMountDocument) => {
    const mountId = routeMountId();
    if (!mountId || !authState()) {
      throw new Error("mount_context_unavailable");
    }

    const routeShare = routeShareId();
    const opened = await openMountedShareDocument(mountId, detail, document);
    const target = createMountedShareDocumentPanelTarget({
      mountId,
      shareId: document.share_id,
      documentId: document.document_id,
      title: opened.title,
      workspaceId: document.workspace_id,
      routePath: routeShare
        ? `/mounts/${mountId}?share=${document.share_id}`
        : `/mounts/${mountId}`,
    });

    activateSharedDocumentRoute(target.targetKey, opened.access);

    if (currentWorkspaceId() !== detail.mount.workspace_id) {
      setCurrentWorkspaceId(detail.mount.workspace_id);
      await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
    }
    workspace.openDocument(target);
  };

  const handlePasswordSubmit = async (event: SubmitEvent) => {
    event.preventDefault();
    const mountId = routeMountId();
    const detail = lockedDetail();
    if (!mountId || !detail || submittingPassword()) return;

    setSubmittingPassword(true);
    setPasswordError(null);
    try {
      await respondShareMountPasswordChallenge(mountId, password());
      const result = await getShareMountForRoute(
        mountId,
        routeShareId(),
        () => {
          return routeMountId() === mountId;
        },
        { allowPasswordBootstrap: true },
      );

      if ("document" in result && result.document) {
        await openDocument(detail, result.document);
        setLockedDetail(null);
        setPassword("");
        return;
      }

      if ("mount" in result) {
        setCurrentWorkspaceId(result.mount.workspace_id);
        setLockedDetail(null);
        setPassword("");
      }
    } catch (err) {
      const retryMs = getRateLimitRetryMs(err);
      setPasswordError(
        retryMs
          ? `Too many attempts. Try again in ${Math.ceil(retryMs / 1000)} seconds.`
          : "Password verification failed.",
      );
    } finally {
      setSubmittingPassword(false);
    }
  };

  createEffect(() => {
    const mountId = routeMountId();
    const shareId = routeShareId();
    const auth = authState();
    const device = deviceState();
    const workerReady = cryptoWorkerReady();
    const openDocs = untrack(() => workspace.openDocuments());
    const routeKey = mountId ? `${mountId}:${shareId ?? "root"}` : null;

    if (!mountId) {
      requestVersion += 1;
      setPendingRouteKey(null);
      return;
    }

    if (!auth || !device || !workerReady) return;
    if (pendingRouteKey() === routeKey) return;

    const alreadyOpen = [...openDocs.values()].some((target) => {
      if (target.source !== "mounted-share-document" || target.mountId !== mountId) return false;
      return shareId ? target.shareId === shareId : target.routePath === `/mounts/${mountId}`;
    });
    if (alreadyOpen) {
      setPendingRouteKey(null);
      return;
    }

    const currentRequest = ++requestVersion;
    setPendingRouteKey(routeKey);

    void (async () => {
      try {
        const anchor = await loadMountTrustAnchor(mountId);
        if (!anchor) {
          setRouteError("Open the original share link to restore this saved share.");
          return;
        }
        setRouteError(null);

        const detail = await getShareMountForRoute(mountId, shareId, () => {
          return (
            currentRequest === requestVersion &&
            routeMountId() === mountId &&
            routeShareId() === shareId
          );
        });
        if (
          currentRequest !== requestVersion ||
          routeMountId() !== mountId ||
          routeShareId() !== shareId
        ) {
          return;
        }

        if (detail.mount.status !== "active") {
          setRouteError("This saved share is no longer available.");
          return;
        }

        if (!detail.document) {
          if (detail.mount.target_kind === "folder" && !shareId) {
            setCurrentWorkspaceId(detail.mount.workspace_id);
            return;
          }
          if (detail.mount.password_protected) {
            try {
              await respondShareMountPasswordChallenge(mountId);
              const restored = await getShareMountForRoute(
                mountId,
                shareId,
                () => {
                  return (
                    currentRequest === requestVersion &&
                    routeMountId() === mountId &&
                    routeShareId() === shareId
                  );
                },
                { allowPasswordBootstrap: true },
              );
              if (
                currentRequest !== requestVersion ||
                routeMountId() !== mountId ||
                routeShareId() !== shareId
              ) {
                return;
              }
              if (restored.document) {
                await openDocument(restored, restored.document);
                return;
              }
              if (restored.mount.target_kind === "folder" && !shareId) {
                setCurrentWorkspaceId(restored.mount.workspace_id);
                return;
              }
            } catch {
              if (
                currentRequest !== requestVersion ||
                routeMountId() !== mountId ||
                routeShareId() !== shareId
              ) {
                return;
              }
            }
            setLockedDetail(detail);
            return;
          }
          setRouteError("This saved share cannot be opened.");
          return;
        }

        await openDocument(detail, detail.document);
      } catch {
        if (
          currentRequest !== requestVersion ||
          routeMountId() !== mountId ||
          routeShareId() !== shareId
        ) {
          return;
        }
        setRouteError("Saved share not found or access denied.");
      } finally {
        if (currentRequest === requestVersion) setPendingRouteKey(null);
      }
    })();
  });

  return (
    <Show
      when={lockedDetail()}
      fallback={
        <Show when={routeError()} fallback={props.fallback}>
          {(message) => (
            <main class="flex min-h-screen items-center justify-center p-6">
              <div class="w-full max-w-md border border-border/60 bg-background/60 p-8 shadow-[var(--glass-shadow-outline)] backdrop-blur">
                <div class="space-y-2">
                  <p class="font-mono text-[10px] uppercase tracking-[0.32em] text-muted-foreground">
                    Saved Share
                  </p>
                  <h1 class="text-xl font-semibold text-foreground">Unable to open share</h1>
                  <p class="text-sm leading-relaxed text-muted-foreground">{message()}</p>
                </div>
              </div>
            </main>
          )}
        </Show>
      }
    >
      <main class="flex min-h-screen items-center justify-center p-6">
        <div class="w-full max-w-md border border-border/60 bg-background/60 p-8 shadow-[var(--glass-shadow-outline)] backdrop-blur">
          <div class="space-y-2">
            <p class="font-mono text-[10px] uppercase tracking-[0.32em] text-muted-foreground">
              Protected Saved Share
            </p>
            <h1 class="text-xl font-semibold text-foreground">Enter password to continue</h1>
            <p class="text-sm leading-relaxed text-muted-foreground">
              This saved share requires the password set by the share owner.
            </p>
          </div>

          <form class="mt-6 space-y-4" onSubmit={handlePasswordSubmit}>
            <Show when={passwordError()}>
              {(message) => (
                <Alert variant="destructive">
                  <AlertDescription>{message()}</AlertDescription>
                </Alert>
              )}
            </Show>

            <Field>
              <FieldLabel for="mount-password">Password</FieldLabel>
              <Input
                id="mount-password"
                type="password"
                value={password()}
                onInput={(event) => setPassword(event.currentTarget.value)}
                autocomplete="current-password"
                placeholder="--------"
                required
                disabled={submittingPassword()}
              />
              <FieldDescription>Saved share</FieldDescription>
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
      </main>
    </Show>
  );
}
