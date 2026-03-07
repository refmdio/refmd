import { splitProps, type ParentProps } from "solid-js"
import * as CheckboxPrimitive from "@kobalte/core/checkbox"
import { CheckIcon } from "lucide-solid"
import { cn } from "@/shared/lib/utils"

function Checkbox(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class", "children", "id"])
  return (
    <CheckboxPrimitive.Root data-slot="checkbox" {...rest}>
      <CheckboxPrimitive.Input id={local.id} />
      <CheckboxPrimitive.Control
        onClick={(event) => event.preventDefault()}
        class={cn(
          "peer size-4 shrink-0 border border-border/60 bg-muted/40 text-foreground/80 shadow-[var(--glass-shadow-inset)] transition-[border,background,color,box-shadow] outline-none",
          "focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
          "aria-invalid:border-destructive aria-invalid:focus-visible:ring-destructive/30 dark:aria-invalid:focus-visible:ring-destructive/40",
          "data-[checked]:bg-foreground data-[checked]:text-background",
          "disabled:cursor-not-allowed disabled:opacity-40",
          "rounded-none",
          local.class
        )}
      >
        <CheckboxPrimitive.Indicator
          data-slot="checkbox-indicator"
          class="flex items-center justify-center text-current transition-none"
        >
          <CheckIcon class="size-3.5" />
        </CheckboxPrimitive.Indicator>
      </CheckboxPrimitive.Control>
      {local.children}
    </CheckboxPrimitive.Root>
  )
}

export { Checkbox }
