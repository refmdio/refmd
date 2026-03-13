import { type JSX, splitProps } from "solid-js";

import { cn } from "@/shared/lib/utils";

function Input(props: JSX.InputHTMLAttributes<HTMLInputElement>) {
  const [local, rest] = splitProps(props, ["class", "type"]);
  return (
    <input
      type={local.type}
      data-slot="input"
      class={cn(
        "file:text-foreground placeholder:text-muted-foreground/70 selection:bg-foreground selection:text-background dark:bg-input/40 border border-border/60 flex h-10 w-full min-w-0 rounded-none bg-muted/40 px-3 text-sm text-foreground/90 shadow-[var(--glass-shadow-inset)] transition-[border,background,color,box-shadow] outline-none file:inline-flex file:h-8 file:rounded-none file:border file:border-border/40 file:bg-muted/60 file:px-2 file:text-[10px] file:font-mono file:uppercase file:tracking-[0.28em] file:text-foreground/80 file:transition-[background,color,border] disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50",
        "focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        "aria-invalid:border-destructive aria-invalid:focus-visible:ring-destructive/30 dark:aria-invalid:focus-visible:ring-destructive/40",
        local.class,
      )}
      {...rest}
    />
  );
}

export { Input };
