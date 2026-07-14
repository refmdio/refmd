import { Match, Show, Switch, type Accessor } from "solid-js";
import { AlertTriangleIcon, CheckCircleIcon, ShieldCheckIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { SafetyNumber } from "../safety-number/SafetyNumber";
import type {
  DeviceRegistrationPhase,
  DeviceRegistrationPublicKeys,
} from "../../model/register/types";
import { PasswordPromptForm } from "./PasswordPromptForm";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

interface DeviceRegistrationPhaseContentProps {
  phase: Accessor<DeviceRegistrationPhase>;
  statusMessage: Accessor<string>;
  isRecoveryMode: Accessor<boolean>;
  identityHybridSigningPublicKeyMaterial: Accessor<HybridSigningPublicKeyMaterial | null>;
  devicePublicKeys: Accessor<DeviceRegistrationPublicKeys | null>;
  clientNonce: Accessor<Uint8Array | null>;
  passwordReentryPassword: Accessor<string>;
  passwordReentryLoading: Accessor<boolean>;
  passwordReentryError: Accessor<string | null>;
  reauthPassword: Accessor<string>;
  reauthLoading: Accessor<boolean>;
  reauthError: Accessor<string | null>;
  error: Accessor<string | null>;
  setPasswordReentryPassword: (value: string) => void;
  setReauthPassword: (value: string) => void;
  submitPasswordReentry: (event: Event) => Promise<void>;
  submitReauth: (event: Event) => Promise<void>;
  beginApproval: () => Promise<void>;
  reloadPage: () => void;
  backToLogin: () => void;
}

export function DeviceRegistrationPhaseContent(props: DeviceRegistrationPhaseContentProps) {
  return (
    <Switch>
      <Match when={props.phase() === "approval_choice"}>
        <div class="space-y-4 py-4">
          <p class="text-sm text-muted-foreground">
            Send an approval request to a device where you are already signed in.
          </p>
          <Button class="w-full" onClick={props.beginApproval}>
            <ShieldCheckIcon />
            Verify with an existing device
          </Button>
        </div>
      </Match>

      <Match when={props.phase() === "generating"}>
        <div class="flex flex-col items-center gap-4 py-8">
          <Spinner class="size-6" />
          <p class="text-sm text-muted-foreground">
            {props.statusMessage() || "Generating device keys..."}
          </p>
        </div>
      </Match>

      <Match when={props.phase() === "waiting"}>
        <div class="space-y-6">
          <div class="space-y-2 text-center">
            <p class="text-sm text-muted-foreground">
              Verify that the same emojis appear on your existing device:
            </p>
          </div>

          <Show
            when={
              props.identityHybridSigningPublicKeyMaterial() &&
              props.devicePublicKeys() &&
              props.clientNonce()
            }
          >
            <SafetyNumber
              deviceId={props.devicePublicKeys()!.deviceId}
              identityHybridSigningPublicKeyMaterial={
                props.identityHybridSigningPublicKeyMaterial()!
              }
              deviceHybridSigningPublicKeyMaterial={
                props.devicePublicKeys()!.hybridSigningPublicKeyMaterial
              }
              deviceHybridEncryptionPublicKeyMaterial={
                props.devicePublicKeys()!.hybridEncryptionPublicKeyMaterial
              }
              deviceEcdhPublic={props.devicePublicKeys()!.ecdhPublic}
              clientNonce={props.clientNonce()!}
              class="py-4"
            />
          </Show>

          <div class="flex flex-col items-center gap-2">
            <Spinner class="size-4" />
            <p class="text-xs text-muted-foreground">
              Waiting for approval from an existing device...
            </p>
          </div>
        </div>
      </Match>

      <Match when={props.phase() === "restoring"}>
        <div class="flex flex-col items-center gap-4 py-8">
          <Spinner class="size-6" />
          <p class="text-sm text-muted-foreground">
            {props.statusMessage() || "Restoring encryption keys..."}
          </p>
        </div>
      </Match>

      <Match when={props.phase() === "done" && props.isRecoveryMode()}>
        <div class="flex flex-col items-center gap-4 py-8">
          <div class="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
            <CheckCircleIcon class="size-6 text-green-600" />
          </div>
          <p class="text-lg font-medium">Recovery Successful!</p>
          <p class="text-sm text-muted-foreground">Redirecting to your workspace&hellip;</p>
        </div>
      </Match>

      <Match when={props.phase() === "done" && !props.isRecoveryMode()}>
        <div class="flex flex-col items-center gap-4 py-8">
          <div class="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
            <CheckCircleIcon class="size-6 text-green-600" />
          </div>
          <p class="text-lg font-medium">Device Ready</p>
          <p class="text-sm text-muted-foreground">
            {props.statusMessage() || "Redirecting to your workspace..."}
          </p>
        </div>
      </Match>

      <Match when={props.phase() === "needs_password"}>
        <PasswordPromptForm
          description="Your browser storage was cleared. Please re-enter your password to continue."
          error={props.passwordReentryError}
          loading={props.passwordReentryLoading}
          value={props.passwordReentryPassword}
          fieldId="password-reentry-password"
          onInput={props.setPasswordReentryPassword}
          onSubmit={props.submitPasswordReentry}
          onCancel={props.backToLogin}
        />
      </Match>

      <Match when={props.phase() === "reauth"}>
        <PasswordPromptForm
          description="Re-enter your password to authorize device registration."
          error={props.reauthError}
          loading={props.reauthLoading}
          value={props.reauthPassword}
          fieldId="reauth-password"
          onInput={props.setReauthPassword}
          onSubmit={props.submitReauth}
          onCancel={props.backToLogin}
        />
      </Match>

      <Match when={props.phase() === "expired"}>
        <div class="space-y-4">
          <Alert variant="destructive">
            <AlertTriangleIcon />
            <AlertDescription>Device registration expired. Please try again.</AlertDescription>
          </Alert>
          <Button class="w-full" onClick={props.reloadPage}>
            Try Again
          </Button>
        </div>
      </Match>

      <Match when={props.phase() === "error"}>
        <div class="space-y-4">
          <Alert variant="destructive">
            <AlertTriangleIcon />
            <AlertDescription>{props.error()}</AlertDescription>
          </Alert>
          <Button class="w-full" onClick={props.backToLogin}>
            Back to Login
          </Button>
        </div>
      </Match>
    </Switch>
  );
}
