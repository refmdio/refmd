import { Progress } from "@/shared/ui/progress";

export type ShareRoutePhase = {
  label: string;
  detail: string;
  value: number;
};

export function ShareRoutePhaseContent(props: { class?: string; phase: ShareRoutePhase }) {
  return (
    <div
      aria-live="polite"
      data-slot="share-route-phase-content"
      class={`w-full max-w-sm space-y-3 text-left${props.class ? ` ${props.class}` : ""}`}
    >
      <div class="space-y-1">
        <p class="text-sm font-medium text-foreground">{props.phase.label}</p>
        <p class="min-h-4 text-xs text-muted-foreground">{props.phase.detail}</p>
      </div>
      <Progress value={props.phase.value} />
    </div>
  );
}
