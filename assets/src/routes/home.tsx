import { Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Button } from "@/shared/ui/button";
import { authState, clearSession } from "@/shared/lib/auth-state";
import { authApi } from "@/shared/api";
import { clearSessionData } from "@/features/auth";

export default function HomePage() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await authApi.logout();
    } finally {
      clearSessionData();
      clearSession();
      navigate("/auth/login");
    }
  };

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <div class="space-y-4 text-center">
        <h1 class="text-2xl font-bold">RefMD</h1>
        <Show
          when={authState()}
          fallback={
            <div class="space-y-2">
              <p class="text-muted-foreground">Not signed in</p>
              <div class="flex gap-2">
                <Button onClick={() => navigate("/auth/login")}>Sign In</Button>
                <Button variant="outline" onClick={() => navigate("/auth/register")}>
                  Create Account
                </Button>
              </div>
            </div>
          }
        >
          {(a) => (
            <div class="space-y-2">
              <p>
                Signed in as <strong>{a().user.email}</strong>
              </p>
              <p class="text-sm text-muted-foreground">
                {a().umk ? "Encryption keys loaded" : "Encryption keys not loaded"}
              </p>
              <Button variant="outline" onClick={handleLogout}>
                Sign Out
              </Button>
            </div>
          )}
        </Show>
      </div>
    </main>
  );
}
