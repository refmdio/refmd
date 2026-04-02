import { createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { Button } from "@/shared/ui/button";
import { Checkbox } from "@/shared/ui/checkbox";
import { Label } from "@/shared/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { LogOutIcon } from "lucide-solid";
import { authState } from "@/entities/session";
import { performLogout } from "@/features/auth";

export function AccountSection() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showLogoutDialog, setShowLogoutDialog] = createSignal(false);
  const [keepCredentials, setKeepCredentials] = createSignal(true);
  const [isLoggingOut, setIsLoggingOut] = createSignal(false);

  const handleLogout = async () => {
    setIsLoggingOut(true);
    try {
      const result = await performLogout(keepCredentials());
      queryClient.clear();
      setShowLogoutDialog(false);
      navigate(result.redirectPath);
    } finally {
      setIsLoggingOut(false);
    }
  };

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">Account</h3>
        <p class="text-sm text-muted-foreground">Manage your account settings.</p>
      </div>

      <Show when={authState()}>
        {(auth) => (
          <section>
            <h4 class="text-sm font-medium mb-3">Profile</h4>
            <div class="p-4 border border-border/60 bg-card space-y-2">
              <div>
                <p class="text-xs text-muted-foreground">Email</p>
                <p class="text-sm font-medium">{auth().user.email}</p>
              </div>
              <div>
                <p class="text-xs text-muted-foreground">User ID</p>
                <p class="text-sm font-mono text-muted-foreground">{auth().user.id}</p>
              </div>
            </div>
          </section>
        )}
      </Show>

      <section class="pt-4 border-t border-border/60">
        <h4 class="text-sm font-medium mb-3">Session</h4>
        <Button
          variant="destructive"
          onClick={() => setShowLogoutDialog(true)}
          class="w-full sm:w-auto"
        >
          <LogOutIcon class="size-4 mr-2" />
          Log out
        </Button>
        <p class="text-xs text-muted-foreground mt-2">You will be signed out of this device.</p>
      </section>

      <Dialog open={showLogoutDialog()} onOpenChange={setShowLogoutDialog}>
        <DialogContent class="max-w-sm">
          <DialogHeader>
            <DialogTitle>Log out</DialogTitle>
            <DialogDescription class="sr-only">Logout confirmation dialog</DialogDescription>
          </DialogHeader>

          <div class="space-y-4">
            <div class="flex items-start gap-3">
              <Checkbox
                id="keep-credentials"
                checked={keepCredentials()}
                onChange={(checked: boolean) => setKeepCredentials(checked)}
                disabled={isLoggingOut()}
              />
              <div class="space-y-1">
                <Label for="keep-credentials" class="text-sm font-medium cursor-pointer">
                  Keep credentials on this device
                </Label>
                <p class="text-xs text-muted-foreground">
                  If unchecked, you will need to enter your password next time you log in.
                </p>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowLogoutDialog(false)}
              disabled={isLoggingOut()}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleLogout} disabled={isLoggingOut()}>
              {isLoggingOut() ? "Logging out..." : "Log out"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
