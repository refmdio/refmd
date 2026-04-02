import { Match, Show, Switch, type Accessor } from "solid-js";
import { AlertTriangleIcon, CheckCircleIcon } from "lucide-solid";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";
import { SafetyNumber } from "../../ui";
import type { DeviceRegistrationPhase, DeviceRegistrationPublicKeys } from "../model/types";
import { PasswordPromptForm } from "./PasswordPromptForm";

interface DeviceRegistrationPhaseContentProps {
  phase: Accessor<DeviceRegistrationPhase>;
  statusMessage: Accessor<string>;
  isRecoveryMode: Accessor<boolean>;
  identitySigningPublic: Accessor<Uint8Array | null>;
  devicePublicKeys: Accessor<DeviceRegistrationPublicKeys | null>;
  clientNonce: Accessor<Uint8Array | null>;
  pdkPassword: Accessor<string>;
  pdkLoading: Accessor<boolean>;
  pdkError: Accessor<string | null>;
  reauthPassword: Accessor<string>;
  reauthLoading: Accessor<boolean>;
  reauthError: Accessor<string | null>;
  error: Accessor<string | null>;
  setPdkPassword: (value: string) => void;
  setReauthPassword: (value: string) => void;
  submitPdkReentry: (event: Event) => Promise<void>;
  submitReauth: (event: Event) => Promise<void>;
  reloadPage: () => void;
  backToLogin: () => void;
}

export function DeviceRegistrationPhaseContent(props: DeviceRegistrationPhaseContentProps) {
  return (
    <Switch>
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
            when={props.identitySigningPublic() && props.devicePublicKeys() && props.clientNonce()}
          >
            <SafetyNumber
              identitySigningPublic={props.identitySigningPublic()!}
              deviceSigningPublic={props.devicePublicKeys()!.signingPublic}
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

      <Match when={props.phase() === "needs_password"}>
        <PasswordPromptForm
          description="Your browser storage was cleared. Please re-enter your password to continue."
          error={props.pdkError}
          loading={props.pdkLoading}
          value={props.pdkPassword}
          fieldId="pdk-password"
          onInput={props.setPdkPassword}
          onSubmit={props.submitPdkReentry}
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
