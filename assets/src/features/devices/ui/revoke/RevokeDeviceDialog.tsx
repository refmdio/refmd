import { createSignal } from "solid-js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { RadioGroup, RadioGroupItem } from "@/shared/ui/radio-group";
import { Spinner } from "@/shared/ui/spinner";
import type { DeviceInfo } from "@/shared/api/devices";
import { isRetireBlockedByUnboundSessionsError, revokeDevice } from "../../lib/revoke/revoke";

interface Props {
  device: DeviceInfo;
  onClose: () => void;
  onRevoked: () => void;
  onError: (msg: string) => void;
}

export function RevokeDeviceDialog(props: Props) {
  const [mode, setMode] = createSignal<"security" | "retire">("security");
  const [loading, setLoading] = createSignal(false);

  const handleRevoke = async () => {
    setLoading(true);
    try {
      const result = await revokeDevice(props.device.id, mode());
      props.onRevoked();
      if (result.warning) {
        props.onError(result.warning);
      }
    } catch (err) {
      if (isRetireBlockedByUnboundSessionsError(err)) {
        props.onError(
          "Cannot use safe removal while a device registration or recovery is in progress. Please complete or cancel it first, or use the 'Lost or compromised' option.",
        );
      } else {
        props.onError(err instanceof Error ? err.message : "Revocation failed");
      }
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
          <DialogTitle>Remove Device</DialogTitle>
          <DialogDescription>Removing "{props.device.name}". Choose the reason:</DialogDescription>
        </DialogHeader>

        <RadioGroup value={mode()} onChange={(v: string) => setMode(v as "security" | "retire")}>
          <div class="space-y-3">
            <label class="flex items-start gap-3 p-3 rounded-lg border cursor-pointer hover:bg-accent/50 transition-colors">
              <RadioGroupItem value="security" />
              <div>
                <span class="font-medium">Lost or compromised</span>
                <p class="text-sm text-muted-foreground mt-1">
                  This device was lost, stolen, or may have been accessed by someone else. All
                  workspace keys will be regenerated.
                </p>
              </div>
            </label>

            <label class="flex items-start gap-3 p-3 rounded-lg border cursor-pointer hover:bg-accent/50 transition-colors">
              <RadioGroupItem value="retire" />
              <div>
                <span class="font-medium">Safely retiring</span>
                <p class="text-sm text-muted-foreground mt-1">
                  This device is in your possession and will be wiped or factory-reset. No key
                  regeneration needed.
                </p>
              </div>
            </label>
          </div>
        </RadioGroup>

        <DialogFooter>
          <Button variant="outline" onClick={props.onClose} disabled={loading()}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleRevoke} disabled={loading()}>
            {loading() ? (
              <span class="flex items-center gap-2">
                <Spinner class="size-3" />
                {mode() === "security" ? "Regenerating keys..." : "Removing..."}
              </span>
            ) : (
              "Remove Device"
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
