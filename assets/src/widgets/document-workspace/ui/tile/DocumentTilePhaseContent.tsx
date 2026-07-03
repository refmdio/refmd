import { Progress } from "@/shared/ui/progress";

export function DocumentTilePhaseContent(props: {
  class?: string;
  detail: string;
  label: string;
  value: number;
}) {
  return (
    <div
      aria-live="polite"
      data-slot="document-tile-phase-content"
      class={`w-full max-w-sm space-y-3 text-left${props.class ? ` ${props.class}` : ""}`}
    >
      <div class="space-y-1">
        <p class="text-sm font-medium text-foreground">{props.label}</p>
        <p class="min-h-4 text-xs text-muted-foreground">{props.detail}</p>
      </div>
      <Progress value={props.value} />
    </div>
  );
}
