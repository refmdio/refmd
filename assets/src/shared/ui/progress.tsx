import { splitProps, type ComponentProps } from "solid-js";
import * as ProgressPrimitive from "@kobalte/core/progress";
import { cn } from "@/shared/lib/utils";

function Progress(props: ComponentProps<typeof ProgressPrimitive.Root>) {
  const [local, rest] = splitProps(props, ["class", "value"]);
  return (
    <ProgressPrimitive.Root data-slot="progress" value={local.value} {...rest}>
      <ProgressPrimitive.Track
        class={cn(
          "relative h-2 w-full overflow-hidden rounded-none border border-border/60 bg-muted/40 shadow-[var(--glass-shadow-inset)]",
          "dark:border-white/20",
          local.class,
        )}
      >
        <ProgressPrimitive.Fill
          data-slot="progress-indicator"
          class={cn(
            "relative h-full w-[var(--kb-progress-fill-width)] bg-foreground transition-all",
            "[&::after]:absolute [&::after]:inset-0 [&::after]:bg-background/20 [&::after]:mix-blend-overlay [&::after]:content-['']",
          )}
        />
      </ProgressPrimitive.Track>
    </ProgressPrimitive.Root>
  );
}

export { Progress };
