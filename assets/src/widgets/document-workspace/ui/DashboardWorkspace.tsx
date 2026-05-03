import { Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { authState } from "@/entities/session";
import { Button } from "@/shared/ui/button";
import { DocumentWorkspace } from "./DocumentWorkspace";

export function DashboardWorkspace() {
  const navigate = useNavigate();

  return (
    <Show
      when={authState()}
      fallback={
        <main class="h-full flex items-center justify-center p-4">
          <div class="space-y-4 text-center">
            <h1 class="text-2xl font-bold">RefMD</h1>
            <p class="text-muted-foreground">Not signed in</p>
            <div class="flex gap-2">
              <Button onClick={() => navigate("/auth/login")}>Sign In</Button>
              <Button variant="outline" onClick={() => navigate("/auth/register")}>
                Create Account
              </Button>
            </div>
          </div>
        </main>
      }
    >
      <DocumentWorkspace />
    </Show>
  );
}
