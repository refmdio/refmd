import { Show, type ParentProps } from "solid-js";
import { Navigate } from "@solidjs/router";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";

export function RequireAuth(props: ParentProps) {
  const canEnterProtectedRoute = () => {
    const auth = authState();
    if (!auth) return false;
    if (auth.needsPasswordReentry) return true;
    return !!deviceState() && cryptoWorkerReady();
  };

  return (
    <Show
      when={canEnterProtectedRoute()}
      fallback={
        <Show when={authState()} fallback={<Navigate href="/auth/login" />}>
          <Navigate href="/devices/register" />
        </Show>
      }
    >
      {props.children}
    </Show>
  );
}

export function RequireGuest(props: ParentProps) {
  return (
    <Show when={!authState()} fallback={<Navigate href="/dashboard" />}>
      {props.children}
    </Show>
  );
}
