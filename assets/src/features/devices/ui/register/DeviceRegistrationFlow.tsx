import { Show } from "solid-js";
import { A } from "@solidjs/router";
import { AlertTriangleIcon, ShieldCheckIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { useDeviceRegistrationFlow } from "../../model/register/use-registration-flow";
import { DeviceRegistrationPhaseContent } from "./DeviceRegistrationPhaseContent";

export function DeviceRegistrationFlow() {
  const flow = useDeviceRegistrationFlow();

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-md">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <ShieldCheckIcon class="size-6" />
            New Device
          </CardTitle>
          <CardDescription>
            {flow.isRecoveryMode() ? (
              "Setting up your recovered device..."
            ) : (
              <>
                Verify this device from an existing device, or{" "}
                <A href="/auth/recovery" class="text-primary underline underline-offset-4">
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
            reloadPage={flow.reloadPage}
            backToLogin={flow.backToLogin}
          />
        </CardContent>
      </Card>
    </main>
  );
}
