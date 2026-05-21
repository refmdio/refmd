import { Match, Switch } from "solid-js";
import { KeyRoundIcon } from "lucide-solid";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Spinner } from "@/shared/ui/spinner";
import { useRecoveryFlow } from "../../model/recovery/use-recovery-flow";
import { RecoveryPhraseForm } from "./RecoveryPhraseForm";
import { RecoveryPasswordSetForm } from "./RecoveryPasswordSetForm";

export function RecoveryFlow() {
  const flow = useRecoveryFlow();

  return (
    <main class="min-h-screen flex items-center justify-center p-4">
      <Card class="w-full max-w-2xl">
        <CardHeader class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-2xl font-bold">
            <KeyRoundIcon class="size-6" />
            {flow.isPasswordReset() ? "Reset Password" : "Recovery Key"}
          </CardTitle>
          <CardDescription>
            {flow.isPasswordReset()
              ? "Enter your 24-word recovery phrase to verify your identity, then set a new password."
              : "Enter your 24-word recovery phrase to restore your encryption keys."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Switch>
            <Match when={flow.phase() === "recovering"}>
              <div class="flex flex-col items-center gap-4 py-12">
                <Spinner class="size-6" />
                <p class="text-muted-foreground">{flow.statusMessage()}</p>
              </div>
            </Match>

            <Match
              when={
                flow.phase() === "password_set" ||
                (flow.phase() === "error" && flow.isPasswordReset() && flow.recoveryKeysLoaded())
              }
            >
              <RecoveryPasswordSetForm
                error={flow.error()}
                loading={flow.loading()}
                newPassword={flow.newPassword()}
                confirmPassword={flow.confirmPassword()}
                onNewPasswordInput={flow.setNewPassword}
                onConfirmPasswordInput={flow.setConfirmPassword}
                onSubmit={flow.submitPasswordSet}
              />
            </Match>

            <Match
              when={
                flow.phase() === "input" ||
                (flow.phase() === "error" && !(flow.isPasswordReset() && flow.recoveryKeysLoaded()))
              }
            >
              <RecoveryPhraseForm
                words={flow.words()}
                loading={flow.loading()}
                error={flow.error()}
                isPasswordReset={flow.isPasswordReset()}
                showTryAgain={flow.phase() === "error"}
                onFileUpload={flow.handleFileUpload}
                onWordChange={flow.handleWordChange}
                onWordKeyDown={flow.handleWordKeyDown}
                onSubmit={flow.submitRecovery}
                onClear={flow.clear}
                onTryAgain={flow.resetInputError}
              />
            </Match>
          </Switch>
        </CardContent>
      </Card>
    </main>
  );
}
