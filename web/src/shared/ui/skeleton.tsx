import { cn } from "@/shared/lib/utils"

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn(
        "animate-pulse rounded-none bg-muted/40 shadow-[var(--glass-shadow-inset)]",
        className
      )}
      {...props}
    />
  )
}

export { Skeleton }
