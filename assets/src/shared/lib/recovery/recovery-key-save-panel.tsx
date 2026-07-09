import { For, type Accessor } from "solid-js";
import { AlertTriangleIcon } from "lucide-solid";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";

interface RecoveryKeySavePanelProps {
  mnemonic: Accessor<string>;
  confirmed: Accessor<boolean>;
  visible: Accessor<boolean>;
  onToggleVisible: () => void;
  onCopy: () => void | Promise<void>;
  onDownload: () => void;
  onContinue: () => void;
  warningDescription: string;
}

export function RecoveryKeySavePanel(props: RecoveryKeySavePanelProps) {
  return (
    <div class="space-y-4">
      <div class="p-4 border rounded">
        <div class="flex items-center justify-between mb-3">
          <span class="text-sm text-muted-foreground">24 words</span>
          <Button variant="ghost" size="sm" onClick={props.onToggleVisible}>
            {props.visible() ? "Hide" : "Show"}
          </Button>
        </div>
        <div class="grid grid-cols-3 gap-2 text-sm">
          <For each={props.mnemonic().split(" ")}>
            {(word, index) => (
              <div class="flex items-center gap-2">
                <span class="text-muted-foreground w-5 text-right">{index() + 1}.</span>
                <span>{props.visible() ? word : "------"}</span>
              </div>
            )}
          </For>
        </div>
      </div>

      <div class="flex gap-2">
        <Button onClick={props.onCopy} variant="outline" class="flex-1">
          Copy
        </Button>
        <Button onClick={props.onDownload} variant="outline" class="flex-1">
          Download
        </Button>
      </div>

      <Alert variant="destructive">
        <AlertTriangleIcon />
        <AlertTitle>Warning</AlertTitle>
        <AlertDescription>{props.warningDescription}</AlertDescription>
      </Alert>

      <Button onClick={props.onContinue} class="w-full" disabled={!props.confirmed()}>
        Continue
      </Button>
    </div>
  );
}
