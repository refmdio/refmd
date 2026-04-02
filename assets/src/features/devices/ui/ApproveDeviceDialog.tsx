import { createEffect, createMemo, createSignal, onCleanup, Show } from "solid-js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
import { SafetyNumber } from "./SafetyNumber";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import { authState } from "@/entities/session";
import {
  approveDeviceRegistration,
  checkPendingDeviceApprovalTofu,
  decodePendingDeviceApprovalKeys,
  rejectDeviceRegistration,
} from "../lib/device-approval";

interface Props {
  device: DeviceRegistrationInfo;
  transferNonce: string | null;
  onClose: () => void;
  onApproved: () => void;
  onError: (msg: string) => void;
}

export function ApproveDeviceDialog(props: Props) {
  const [loading, setLoading] = createSignal(false);
  const [step, setStep] = createSignal<"verify" | "distributing">("verify");
  const [tofuBlocked, setTofuBlocked] = createSignal<string | null>(null);
  const [tofuChecked, setTofuChecked] = createSignal(false);

  const identitySigningPublic = () => {
    const auth = authState();
    return auth?.identitySigningPublic ?? null;
  };
  const decodedDeviceKeys = createMemo(() => decodePendingDeviceApprovalKeys(props.device));

  createEffect(() => {
    const deviceId = props.device.id;
    let cancelled = false;

    setTofuBlocked(null);
    setTofuChecked(false);

    void (async () => {
      try {
        const blocked = await checkPendingDeviceApprovalTofu(props.device);
        if (cancelled || props.device.id !== deviceId) return;
        setTofuBlocked(blocked);
      } catch {
        if (cancelled || props.device.id !== deviceId) return;
        setTofuBlocked("Key verification failed. Cannot verify device authenticity.");
      } finally {
        if (!cancelled && props.device.id === deviceId) {
          setTofuChecked(true);
        }
      }
    })();

    onCleanup(() => {
      cancelled = true;
    });
  });

  const handleApprove = async () => {
    setLoading(true);
    try {
      setStep("verify");
      await approveDeviceRegistration({
        device: props.device,
        transferNonce: props.transferNonce,
        onStepChange: setStep,
      });
      props.onApproved();
    } catch (err) {
      props.onError(err instanceof Error ? err.message : "Approval failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog
      open
      onOpenChange={(open: boolean) => {
        if (!open) props.onClose();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Approve New Device</DialogTitle>
          <DialogDescription>
            "{props.device.name}" ({props.device.device_type}) is requesting access. Verify that the
            emojis below match the ones shown on the new device.
          </DialogDescription>
        </DialogHeader>

        <Show when={tofuBlocked()}>
          <Alert variant="destructive">
            <AlertDescription>{tofuBlocked()}</AlertDescription>
          </Alert>
        </Show>

        <Show when={!tofuChecked()}>
          <div class="flex items-center gap-2 py-4">
            <Spinner class="size-4" />
            <span class="text-sm text-muted-foreground">Verifying device keys...</span>
          </div>
        </Show>

        <Show when={tofuChecked() && !tofuBlocked() && identitySigningPublic()}>
          <SafetyNumber
            identitySigningPublic={identitySigningPublic()!}
            deviceSigningPublic={decodedDeviceKeys().deviceSigningPublic}
            deviceEcdhPublic={decodedDeviceKeys().deviceEcdhPublic}
            clientNonce={decodedDeviceKeys().clientNonce}
            class="py-4"
          />
        </Show>

        <Show when={step() === "distributing"}>
          <Alert>
            <AlertDescription class="flex items-center gap-2">
              <Spinner class="size-3" />
              Distributing encryption keys...
            </AlertDescription>
          </Alert>
        </Show>

        <DialogFooter>
          <Button
            variant="destructive"
            onClick={async () => {
              await rejectDeviceRegistration(props.device.id);
              props.onClose();
            }}
            disabled={loading()}
          >
            Reject
          </Button>
          <Button onClick={handleApprove} disabled={loading() || !tofuChecked() || !!tofuBlocked()}>
            {loading() ? (
              <span class="flex items-center gap-2">
                <Spinner class="size-3" />
                {step() === "verify" ? "Approving..." : "Distributing keys..."}
              </span>
            ) : (
              "Emojis Match - Approve"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
