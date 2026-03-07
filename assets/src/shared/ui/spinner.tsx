import { type JSX, splitProps } from "solid-js"
import { Loader2Icon } from "lucide-solid"

import { cn } from "@/shared/lib/utils"

function Spinner(props: JSX.SvgSVGAttributes<SVGSVGElement>) {
  const [local, rest] = splitProps(props, ["class"])
  return (
    <Loader2Icon
      role="status"
      aria-label="Loading"
      data-slot="spinner"
      class={cn(
        "size-4 animate-spin text-foreground/80 drop-shadow-[var(--glass-drop-shadow-subtle)]",
        "dark:text-foreground",
        local.class
      )}
      {...rest}
    />
  )
}

export { Spinner }
