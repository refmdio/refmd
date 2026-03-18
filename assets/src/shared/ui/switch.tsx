import { splitProps, type ParentProps } from "solid-js";
import * as SwitchPrimitive from "@kobalte/core/switch";
import { cn } from "@/shared/lib/utils";

function Switch(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <SwitchPrimitive.Root data-slot="switch" {...rest}>
      <SwitchPrimitive.Input />
      <SwitchPrimitive.Control
        class={cn(
          "peer inline-flex h-5 w-9 shrink-0 items-center border border-border/60 bg-muted/50 text-foreground/80 transition-[border,background,color,transform] outline-none disabled:cursor-not-allowed disabled:opacity-40",
          "data-[checked]:bg-foreground data-[checked]:text-background",
          "focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
          "rounded-none",
          local.class,
        )}
      >
        <SwitchPrimitive.Thumb
          data-slot="switch-thumb"
          class={cn(
            "pointer-events-none block size-4 border border-border/60 bg-muted/70 text-current transition-transform",
            "translate-x-0",
            "data-[checked]:translate-x-[calc(100%-2px)]",
            "rounded-none",
          )}
        />
      </SwitchPrimitive.Control>
    </SwitchPrimitive.Root>
  );
}

export { Switch };
