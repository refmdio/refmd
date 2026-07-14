import { Show, type ParentProps } from "solid-js";
import { Navigate, useLocation } from "@solidjs/router";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { isSecureLogoutIncomplete } from "@/shared/lib/auth/logout-incomplete";

export function RequireAuth(props: ParentProps) {
  const location = useLocation();
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
        <Show
          when={authState()}
          fallback={<Navigate href={retainLogoutIncomplete("/auth/login", location.search)} />}
        >
          <Navigate href={retainLogoutIncomplete("/devices/register", location.search)} />
        </Show>
      }
    >
      {props.children}
    </Show>
  );
}

export function RequireGuest(props: ParentProps) {
  const location = useLocation();
  if (isSecureLogoutIncomplete()) {
    return location.pathname === "/auth/login" ? (
      props.children
    ) : (
      <Navigate href="/auth/login?logout_incomplete=true" />
    );
  }
  return (
    <Show
      when={!authState()}
      fallback={<Navigate href={retainLogoutIncomplete("/dashboard", location.search)} />}
    >
      {props.children}
    </Show>
  );
}

export function RequireSecureLogoutComplete(props: ParentProps) {
  const location = useLocation();
  const redirect = secureLogoutRedirect(location.pathname, isSecureLogoutIncomplete());
  return redirect ? <Navigate href={redirect} /> : props.children;
}

export function secureLogoutRedirect(pathname: string, incomplete: boolean): string | null {
  return incomplete && pathname !== "/auth/login" ? "/auth/login?logout_incomplete=true" : null;
}

export function retainLogoutIncomplete(path: string, search: string): string {
  const params = new URLSearchParams(search);
  return params.get("logout_incomplete") === "true" ? `${path}?logout_incomplete=true` : path;
}
