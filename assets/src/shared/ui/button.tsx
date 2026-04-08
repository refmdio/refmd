import { type JSX, splitProps, Show } from "solid-js";
import { Dynamic } from "solid-js/web";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/shared/lib/utils";

const buttonVariants = cva(
  "relative inline-flex items-center justify-center gap-2 font-mono uppercase tracking-[0.28em] text-[11px] transition-[color,background,opacity,transform] duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-40 isolate overflow-hidden text-[color:var(--button-text)]",
  {
    variants: {
      variant: {
        default:
          "border border-foreground px-4 h-10 [--button-text:var(--foreground)] transition-colors before:absolute before:inset-0 before:[z-index:-1] before:origin-left before:scale-x-0 before:rounded-[inherit] before:bg-foreground before:opacity-100 before:transition-transform before:duration-200 before:content-[''] hover:[--button-text:var(--background)] hover:border-background hover:before:scale-x-100 active:[--button-text:var(--background)] active:border-background active:before:scale-x-100",
        destructive:
          "border border-transparent bg-destructive/90 text-destructive-foreground px-4 h-10 hover:bg-destructive active:bg-destructive focus-visible:ring-destructive/40",
        outline:
          "border border-border/70 bg-background/30 px-4 h-10 text-foreground transition-colors hover:border-foreground hover:bg-foreground/10 active:border-foreground active:bg-foreground/10",
        secondary:
          "border border-transparent bg-muted/50 px-4 h-10 text-foreground/80 hover:bg-muted/70 hover:text-foreground active:bg-muted/70 active:text-foreground",
        ghost:
          "border border-transparent text-muted-foreground transition-colors hover:text-foreground hover:[text-shadow:0_0_14px_rgba(255,255,255,0.35)] active:text-foreground active:[text-shadow:0_0_14px_rgba(255,255,255,0.35)] focus-visible:text-foreground focus-visible:[text-shadow:0_0_16px_rgba(148,163,184,0.55)]",
        muted:
          "border border-border/60 bg-muted/40 px-3 h-9 text-muted-foreground transition-colors hover:text-foreground hover:border-border hover:bg-muted/60 active:text-foreground active:border-border active:bg-muted/60",
        link: "px-2 py-1 text-muted-foreground tracking-[0.3em] hover:text-foreground active:text-foreground after:absolute after:bottom-0 after:left-0 after:h-px after:w-full after:origin-left after:scale-x-0 after:bg-foreground after:transition-transform after:duration-200 after:ease-out after:content-[''] hover:after:scale-x-100 active:after:scale-x-100 focus-visible:after:scale-x-100",
      },
      size: {
        default: "h-10 px-4",
        sm: "h-9 px-3",
        lg: "h-11 px-5",
        icon: "size-9",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export type ButtonProps = JSX.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  };

function Button(props: ButtonProps) {
  const [local, rest] = splitProps(props, ["class", "variant", "size", "children", "asChild"]);

  return (
    <Dynamic
      component={local.asChild ? "span" : "button"}
      data-variant={local.variant}
      class={cn(buttonVariants({ variant: local.variant, size: local.size }), local.class)}
      {...rest}
    >
      <Show when={!local.asChild} fallback={local.children}>
        <span class="relative z-10 inline-flex items-center justify-center gap-2 leading-none tracking-[0.2em] text-[inherit]">
          {local.children}
        </span>
      </Show>
    </Dynamic>
  );
}

export { Button, buttonVariants };
