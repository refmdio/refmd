import { createSignal, For, Show } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { Button } from "@/shared/ui/button";
import { Checkbox } from "@/shared/ui/checkbox";
import { Input } from "@/shared/ui/input";
import { Label } from "@/shared/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { LinkIcon, LockKeyholeIcon, LogOutIcon, Trash2Icon } from "lucide-solid";
import { authState, cryptoWorkerReady } from "@/entities/session";
import {
  OAuthProviderButtons,
  performLogout,
  ProviderIcon,
  providerLabel,
  setupAccountPassword,
} from "@/features/auth";
import { ApiError, authApi, type OAuthProvider } from "@/shared/api";
import { clearAllDocumentStates } from "@/features/editor";

const AUTH_METHODS_QUERY_KEY = ["auth", "external-accounts"] as const;

export function AccountSection() {
  const queryClient = useQueryClient();
  const [showLogoutDialog, setShowLogoutDialog] = createSignal(false);
  const [keepCredentials, setKeepCredentials] = createSignal(true);
  const [isLoggingOut, setIsLoggingOut] = createSignal(false);
  const [linkingProvider, setLinkingProvider] = createSignal<OAuthProvider | null>(null);
  const [unlinkingProvider, setUnlinkingProvider] = createSignal<OAuthProvider | null>(null);
  const [newPassword, setNewPassword] = createSignal("");
  const [confirmPassword, setConfirmPassword] = createSignal("");
  const [isSettingPassword, setIsSettingPassword] = createSignal(false);
  const [authMethodError, setAuthMethodError] = createSignal<string | null>(null);

  const authMethods = createQuery(() => ({
    queryKey: AUTH_METHODS_QUERY_KEY,
    queryFn: authApi.externalAccounts,
  }));

  const accounts = () => authMethods.data?.accounts ?? [];
  const availableProviders = () => (authMethods.data?.available_providers ?? []) as OAuthProvider[];
  const linkedProviders = () => new Set(accounts().map((account) => account.provider));
  const linkableProviders = () =>
    availableProviders().filter((provider) => !linkedProviders().has(provider));

  const handleLogout = async () => {
    setIsLoggingOut(true);
    try {
      clearAllDocumentStates({ flushCache: false });
      const result = await performLogout(keepCredentials());
      queryClient.clear();
      setShowLogoutDialog(false);
      window.location.replace(result.redirectPath);
    } finally {
      setIsLoggingOut(false);
    }
  };

  const handleStartLink = async (provider: OAuthProvider) => {
    setAuthMethodError(null);
    setLinkingProvider(provider);
    try {
      const response = await authApi.oauthLinkStart(provider, {
        return_to: "/dashboard?settings=account",
      });
      window.location.assign(response.authorization_url);
    } catch (error) {
      setAuthMethodError(authMethodErrorMessage(error, provider));
      setLinkingProvider(null);
    }
  };

  const handleUnlink = async (provider: OAuthProvider) => {
    setAuthMethodError(null);
    setUnlinkingProvider(provider);
    try {
      await authApi.unlinkExternalAccount(provider);
      await queryClient.invalidateQueries({ queryKey: AUTH_METHODS_QUERY_KEY });
    } catch (error) {
      setAuthMethodError(authMethodErrorMessage(error, provider));
    } finally {
      setUnlinkingProvider(null);
    }
  };

  const handlePasswordSetup = async (event: Event) => {
    event.preventDefault();
    const auth = authState();
    const password = newPassword();

    setAuthMethodError(null);

    if (!auth) {
      setAuthMethodError("Session is no longer available.");
      return;
    }

    if (password.length < 8) {
      setAuthMethodError("Password must be at least 8 characters.");
      return;
    }

    if (password !== confirmPassword()) {
      setAuthMethodError("Passwords do not match.");
      return;
    }

    setIsSettingPassword(true);
    try {
      await setupAccountPassword(auth, password);
      setNewPassword("");
      setConfirmPassword("");
      await queryClient.invalidateQueries({ queryKey: AUTH_METHODS_QUERY_KEY });
    } catch (error) {
      setAuthMethodError(authMethodErrorMessage(error));
    } finally {
      setIsSettingPassword(false);
    }
  };

  const canUnlinkProvider = (provider: OAuthProvider) => {
    if (!authMethods.data) return false;
    if (authMethods.data.password_configured) return true;
    return accounts().some((account) => account.provider !== provider);
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
              <div class="border-t border-border/60 pt-4">
                <div class="mb-3 flex items-center gap-2">
                  <LinkIcon class="size-4 text-muted-foreground" />
                  <p class="text-sm font-medium">Sign-in methods</p>
                </div>
                <Show
                  when={authMethods.data}
                  fallback={
                    <p class="text-sm text-muted-foreground">
                      {authMethods.isLoading
                        ? "Loading sign-in methods..."
                        : "Sign-in methods unavailable."}
                    </p>
                  }
                >
                  {(methods) => (
                    <div class="space-y-4">
                      <div class="divide-y divide-border/60">
                        <For each={accounts()}>
                          {(account) => {
                            const provider = account.provider as OAuthProvider;
                            return (
                              <div class="flex items-center justify-between gap-3 py-3 first:pt-0">
                                <div class="flex min-w-0 items-center gap-3">
                                  <ProviderIcon provider={provider} />
                                  <div class="min-w-0">
                                    <p class="text-sm font-medium">{providerLabel(provider)}</p>
                                    <Show when={account.email}>
                                      {(email) => (
                                        <p class="truncate text-xs text-muted-foreground">
                                          {email()}
                                        </p>
                                      )}
                                    </Show>
                                  </div>
                                </div>
                                <Show
                                  when={canUnlinkProvider(provider)}
                                  fallback={
                                    <span class="shrink-0 text-xs text-muted-foreground">
                                      Required
                                    </span>
                                  }
                                >
                                  <Button
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    class="shrink-0 font-sans text-sm normal-case tracking-normal"
                                    disabled={unlinkingProvider() !== null}
                                    onClick={() => void handleUnlink(provider)}
                                  >
                                    <Trash2Icon class="size-4" />
                                    Unlink
                                  </Button>
                                </Show>
                              </div>
                            );
                          }}
                        </For>

                        <Show when={methods().password_configured}>
                          <div class="flex items-center justify-between gap-3 py-3 first:pt-0">
                            <div class="flex min-w-0 items-center gap-3">
                              <LockKeyholeIcon class="size-5 shrink-0 text-muted-foreground" />
                              <div class="min-w-0">
                                <p class="text-sm font-medium">Password</p>
                                <p class="text-xs text-muted-foreground">Enabled</p>
                              </div>
                            </div>
                          </div>
                        </Show>
                      </div>

                      <Show when={linkableProviders().length > 0}>
                        <div class="space-y-2">
                          <p class="text-xs text-muted-foreground">Add another provider</p>
                          <OAuthProviderButtons
                            providers={linkableProviders()}
                            loadingProvider={linkingProvider()}
                            actionLabel="Link"
                            disabled={unlinkingProvider() !== null || isSettingPassword()}
                            onStart={(provider) => void handleStartLink(provider)}
                          />
                        </div>
                      </Show>

                      <Show when={!methods().password_configured}>
                        <form
                          class="space-y-3 border-t border-border/60 pt-4"
                          onSubmit={handlePasswordSetup}
                        >
                          <p class="text-xs text-muted-foreground">Add password sign-in</p>
                          <div class="grid gap-3 sm:grid-cols-2">
                            <div class="space-y-1.5">
                              <Label for="account-new-password">Password</Label>
                              <Input
                                id="account-new-password"
                                type="password"
                                autocomplete="new-password"
                                value={newPassword()}
                                disabled={!cryptoWorkerReady() || isSettingPassword()}
                                onInput={(event) => setNewPassword(event.currentTarget.value)}
                              />
                            </div>
                            <div class="space-y-1.5">
                              <Label for="account-confirm-password">Confirm password</Label>
                              <Input
                                id="account-confirm-password"
                                type="password"
                                autocomplete="new-password"
                                value={confirmPassword()}
                                disabled={!cryptoWorkerReady() || isSettingPassword()}
                                onInput={(event) => setConfirmPassword(event.currentTarget.value)}
                              />
                            </div>
                          </div>
                          <Button
                            type="submit"
                            variant="outline"
                            class="w-full font-sans text-sm normal-case tracking-normal sm:w-auto"
                            disabled={!cryptoWorkerReady() || isSettingPassword()}
                          >
                            {isSettingPassword() ? "Saving..." : "Set password"}
                          </Button>
                        </form>
                      </Show>

                      <Show when={authMethodError()}>
                        {(message) => <p class="text-sm text-destructive">{message()}</p>}
                      </Show>
                    </div>
                  )}
                </Show>
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
                  Turning this off performs Secure Logout: saved credentials and local encrypted
                  caches are removed from this browser.
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

function authMethodErrorMessage(error: unknown, provider?: OAuthProvider): string {
  const providerName = provider ? providerLabel(provider) : "Authentication";

  if (error instanceof ApiError) {
    if (error.code === "last_auth_method_required") {
      return "Add another sign-in method before removing this one.";
    }
    if (error.code === "oauth_external_account_conflict") {
      return `${providerName} is already linked to another account.`;
    }
    if (error.code === "password_already_configured") {
      return "Password sign-in is already enabled.";
    }
    if (error.code === "oauth_provider_not_configured") {
      return `${providerName} is not configured on this server.`;
    }
  }

  return error instanceof Error ? error.message : "Authentication method update failed.";
}
