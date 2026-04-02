import { Show, type ParentProps } from "solid-js";
import { Navigate } from "@solidjs/router";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";

export function RequireAuth(props: ParentProps) {
  return (
    <Show
      when={authState() && deviceState() && cryptoWorkerReady()}
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
