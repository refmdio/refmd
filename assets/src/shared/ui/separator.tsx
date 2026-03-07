import { type JSX, splitProps, mergeProps } from "solid-js"
import * as SeparatorPrimitive from "@kobalte/core/separator"

import { cn } from "@/shared/lib/utils"

type SeparatorProps = JSX.HTMLAttributes<HTMLHRElement> & {
  orientation?: "horizontal" | "vertical"
  decorative?: boolean
}

function Separator(props: SeparatorProps) {
  const merged = mergeProps(
    { orientation: "horizontal" as const, decorative: true },
    props
  )
  const [local, rest] = splitProps(merged, ["class", "orientation", "decorative"])

  return (
    <SeparatorPrimitive.Root
      as="div"
      data-slot="separator"
      orientation={local.orientation}
      aria-hidden={local.decorative ? "true" : undefined}
      class={cn(
        "relative isolate shrink-0 overflow-hidden border-0 data-[orientation=horizontal]:h-px data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-px",
        "after:absolute after:inset-0 after:content-[''] after:bg-border/60",
        "data-[orientation=horizontal]:after:bg-gradient-to-r data-[orientation=horizontal]:after:from-transparent data-[orientation=horizontal]:after:via-border/60 data-[orientation=horizontal]:after:to-transparent",
        "data-[orientation=vertical]:after:bg-gradient-to-b data-[orientation=vertical]:after:from-transparent data-[orientation=vertical]:after:via-border/60 data-[orientation=vertical]:after:to-transparent",
        "dark:data-[orientation=horizontal]:after:via-white/20 dark:data-[orientation=vertical]:after:via-white/20",
        local.class
      )}
      {...rest}
    />
  )
}

export { Separator }
