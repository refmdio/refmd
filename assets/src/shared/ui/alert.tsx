import { type JSX, splitProps } from "solid-js";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/shared/lib/utils";
import { toneVarDefaults, toneVarOverrides } from "@/shared/lib/tone";

const alertVariants = cva(
  [
    toneVarDefaults,
    "group/alert relative grid w-full grid-cols-[auto_1fr] items-start gap-x-4 gap-y-3 overflow-hidden rounded-none border border-[color:var(--tone-border)] px-6 py-5 text-sm text-[color:var(--tone-body)] shadow-[var(--glass-shadow-outline)] backdrop-blur-[12px] transition-colors",
    "before:absolute before:left-0 before:top-3 before:bottom-3 before:w-[3px] before:rounded-full before:bg-[color:var(--tone-bar)] before:content-['']",
    "after:absolute after:inset-x-0 after:top-0 after:h-px after:bg-[image:var(--tone-gradient)] after:bg-no-repeat after:bg-[length:100%_100%] after:content-['']",
    "[&>svg]:col-start-1 [&>svg]:row-span-2 [&>svg]:mt-1 [&>svg]:size-5 [&>svg]:rounded-full [&>svg]:border [&>svg]:border-[color:var(--tone-icon-border)] [&>svg]:bg-[color:var(--tone-icon-bg)] [&>svg]:p-1 [&>svg]:text-[color:var(--tone-icon-fg)]",
  ].join(" "),
  {
    variants: {
      variant: {
        default: toneVarOverrides.default,
        info: toneVarOverrides.info,
        success: toneVarOverrides.success,
        warning: toneVarOverrides.warning,
        destructive: toneVarOverrides.destructive,
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

type AlertProps = JSX.HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>;

function Alert(props: AlertProps) {
  const [local, rest] = splitProps(props, ["class", "variant"]);
  const tone = () => local.variant ?? "default";

  return (
    <div
      data-slot="alert"
      data-variant={tone()}
      role="alert"
      class={cn(alertVariants({ variant: tone() }), local.class)}
      {...rest}
    />
  );
}

function AlertTitle(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="alert-title"
      class={cn(
        "col-start-2 font-mono text-[10px] uppercase tracking-[0.32em] text-[color:var(--tone-title)]",
        local.class,
      )}
      {...rest}
    />
  );
}

function AlertDescription(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="alert-description"
      class={cn(
        "col-start-2 grid justify-items-start gap-2 text-left text-sm text-[color:var(--tone-description)] [&_p]:leading-relaxed",
        local.class,
      )}
      {...rest}
    />
  );
}

function AlertActions(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="alert-actions"
      class={cn(
        "col-start-2 flex flex-wrap items-center gap-2 pt-1 text-[10px] font-mono uppercase tracking-[0.32em] text-[color:var(--tone-title)]",
        local.class,
      )}
      {...rest}
    />
  );
}

export { Alert, AlertActions, AlertDescription, AlertTitle, alertVariants };
