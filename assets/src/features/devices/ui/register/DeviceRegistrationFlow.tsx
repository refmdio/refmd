import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { AlertTriangleIcon, ShieldCheckIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { RecoveryKeySavePanel } from "@/shared/lib/recovery/recovery-key-save-panel";
import { useDeviceRegistrationFlow } from "../../model/register/use-registration-flow";
import { DeviceRegistrationPhaseContent } from "./DeviceRegistrationPhaseContent";

export function DeviceRegistrationFlow() {
  const flow = useDeviceRegistrationFlow();

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-lg">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <ShieldCheckIcon class="size-6" />
            {flow.oauthRecoveryMnemonic() ? "Recovery Key" : "New Device"}
          </CardTitle>
          <CardDescription>
            {flow.oauthRecoveryMnemonic() ? (
              "Save this recovery key in a safe place. You will need it if you lose access to all your devices."
            ) : flow.isRecoveryMode() ? (
              "Setting up your recovered device..."
            ) : (
              <>
                Verify this device from an existing device, or{" "}
                <A
                  href="/auth/recovery"
                  class="text-primary underline underline-offset-4"
                  onClick={flow.openRecovery}
                >
                  use your recovery key
                </A>
                .
              </>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Show when={flow.dskUnavailableOAuth()}>
            <Alert class="mb-4">
              <AlertTriangleIcon />
              <AlertDescription>
                Your browser does not support persistent key storage. Device keys will only be
                available for this session. After closing the browser, you will need to re-approve
                this device. Consider using password authentication for persistent access.
              </AlertDescription>
            </Alert>
          </Show>

          <Show
            when={flow.oauthRecoveryMnemonic()}
            fallback={
              <DeviceRegistrationPhaseContent
                phase={flow.phase}
                statusMessage={flow.statusMessage}
                isRecoveryMode={flow.isRecoveryMode}
                identityHybridSigningPublicKeyMaterial={flow.identityHybridSigningPublicKeyMaterial}
                devicePublicKeys={flow.devicePublicKeys}
                clientNonce={flow.clientNonce}
                passwordReentryPassword={flow.passwordReentryPassword}
                passwordReentryLoading={flow.passwordReentryLoading}
                passwordReentryError={flow.passwordReentryError}
                reauthPassword={flow.reauthPassword}
                reauthLoading={flow.reauthLoading}
                reauthError={flow.reauthError}
                error={flow.error}
                setPasswordReentryPassword={flow.setPasswordReentryPassword}
                setReauthPassword={flow.setReauthPassword}
                submitPasswordReentry={flow.submitPasswordReentry}
                submitReauth={flow.submitReauth}
                beginApproval={flow.beginApproval}
                reloadPage={flow.reloadPage}
                backToLogin={flow.backToLogin}
              />
            }
          >
            {(mnemonic) => (
              <RecoveryKeySavePanel
                mnemonic={mnemonic}
                confirmed={flow.oauthRecoveryKeyConfirmed}
                visible={flow.oauthRecoveryKeyVisible}
                onToggleVisible={flow.toggleOAuthRecoveryKeyVisible}
                onCopy={flow.copyOAuthRecoveryKey}
                onDownload={flow.downloadOAuthRecoveryKey}
                onContinue={flow.confirmOAuthRecoveryKey}
                warningDescription="If you lose this recovery key and lose access to all devices, OAuth login alone cannot recover your encrypted data."
              />
            )}
          </Show>
        </CardContent>
      </Card>
    </main>
  );
}
