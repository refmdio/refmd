import { restoreSessionContext } from "@/entities/session";
import { setPreferredSessionScope } from "@/shared/lib/auth/session-scope";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";
import { clearActiveShareSocketSlug } from "../bootstrap/document";

let activeShareRouteCount = 0;
let leaveTimer: number | null = null;

export function enterShareRouteSession(): void {
  if (leaveTimer != null) {
    window.clearTimeout(leaveTimer);
    leaveTimer = null;
  }

  activeShareRouteCount += 1;
  setPreferredSessionScope("share");
}

export function leaveShareRouteSession(): void {
  activeShareRouteCount = Math.max(0, activeShareRouteCount - 1);
  if (activeShareRouteCount > 0) return;

  setPreferredSessionScope(null);

  leaveTimer = window.setTimeout(() => {
    leaveTimer = null;
    if (activeShareRouteCount > 0) return;

    resetPhoenixConnection();
    clearActiveShareSocketSlug();

    if (!window.location.pathname.startsWith("/share/")) {
      void restoreSessionContext();
    }
  }, 0);
}
