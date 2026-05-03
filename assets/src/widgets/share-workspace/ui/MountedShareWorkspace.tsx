import { createEffect, createSignal, Show, untrack, type JSX } from "solid-js";
import { useNavigate, useParams, useSearchParams } from "@solidjs/router";
import { getShareMount, type ShareMountAdmission, type ShareMountDetail } from "@/entities/mount";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { activateSharedDocumentRoute } from "@/features/editor";
import { createMountedShareDocumentPanelTarget, usePanelWorkspace } from "@/features/panel";
import { resolveMountedShareOpen, respondShareMountPasswordChallenge } from "@/features/share";
import { getRateLimitRetryMs } from "@/shared/api";
import { Notice } from "@/shared/lib/notice";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

export function MountedShareWorkspace(props: { fallback: JSX.Element }) {
  const navigate = useNavigate();
  const params = useParams<{ mountId?: string }>();
  const [searchParams] = useSearchParams();
  const workspace = usePanelWorkspace();
  const [pendingRouteKey, setPendingRouteKey] = createSignal<string | null>(null);
  const [lockedDetail, setLockedDetail] = createSignal<ShareMountDetail | null>(null);
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

  const openAdmission = async (detail: ShareMountDetail, admission: ShareMountAdmission) => {
    const mountId = routeMountId();
    const auth = authState();
    const device = deviceState();
    if (!mountId || !auth || !device?.deviceSigningPublic || !device.deviceEcdhPublic) {
      throw new Error("mount_context_unavailable");
    }

    const routeShare = routeShareId();
    const opened = await resolveMountedShareOpen(mountId, detail, admission, {
      principalId: auth.user.id,
      displayName: auth.user.name,
      deviceId: device.deviceId,
      signingPublicKey: device.deviceSigningPublic,
      encryptionPublicKey: device.deviceEcdhPublic,
    });
    const target = createMountedShareDocumentPanelTarget({
      mountId,
      shareId: admission.share_id,
      documentId: admission.document_id,
      title: opened.title,
      workspaceId: detail.mount.workspace_id,
      routePath: routeShare
        ? `/mounts/${mountId}?share=${admission.share_id}`
        : `/mounts/${mountId}`,
    });

    activateSharedDocumentRoute(target.targetKey, opened.access);

    setCurrentWorkspaceId(detail.mount.workspace_id);
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
      const result = await respondShareMountPasswordChallenge(mountId, password(), {
        shareId: routeShareId(),
      });

      if ("admission" in result && result.admission) {
        await openAdmission(detail, result.admission);
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
      if (shareId) return target.shareId === shareId;
      return false;
    });
    if (alreadyOpen) {
      setPendingRouteKey(null);
      return;
    }

    if (!device.deviceSigningPublic || !device.deviceEcdhPublic) {
      new Notice("Device keys are not ready. Please reload and try again.");
      navigate("/dashboard", { replace: true, scroll: false });
      return;
    }

    const currentRequest = ++requestVersion;
    setPendingRouteKey(routeKey);

    void (async () => {
      try {
        const detail = await getShareMount(mountId, { shareId });
        if (
          currentRequest !== requestVersion ||
          routeMountId() !== mountId ||
          routeShareId() !== shareId
        ) {
          return;
        }

        if (detail.mount.status !== "active") {
          new Notice("This saved share is no longer available.");
          navigate("/dashboard", { replace: true, scroll: false });
          return;
        }

        if (!detail.admission) {
          if (detail.mount.password_protected) {
            setLockedDetail(detail);
            return;
          }
          if (detail.mount.target_kind === "folder" && !shareId) {
            setCurrentWorkspaceId(detail.mount.workspace_id);
            return;
          }
          new Notice("This saved share cannot be opened.");
          return;
        }

        await openAdmission(detail, detail.admission);
      } catch {
        if (
          currentRequest !== requestVersion ||
          routeMountId() !== mountId ||
          routeShareId() !== shareId
        ) {
          return;
        }
        new Notice("Saved share not found or access denied.");
        navigate("/dashboard", { replace: true, scroll: false });
      } finally {
        if (currentRequest === requestVersion) setPendingRouteKey(null);
      }
    })();
  });

  return (
    <Show when={lockedDetail()} fallback={props.fallback}>
      {(detail) => (
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
                <FieldDescription>{detail().mount.title ?? "Saved share"}</FieldDescription>
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
      )}
    </Show>
  );
}
