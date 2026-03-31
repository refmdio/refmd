import {
  type Component,
  type ComponentProps,
  type JSX,
  splitProps,
  createSignal,
  createEffect,
  onCleanup,
} from "solid-js";

import { Toaster as Sonner } from "solid-sonner";
import { CheckCheck, Info, TriangleAlert } from "lucide-solid";

import { cn } from "@/shared/lib/utils";
import { getCspNonce } from "@/shared/lib/csp-nonce";
import { toneVarDefaults, toneVarOverrides } from "@/shared/lib/tone";

type ToasterProps = ComponentProps<typeof Sonner>;

const toastBaseClass = cn(
  toneVarDefaults,
  "group/toast relative grid min-w-[20rem] max-w-[420px] grid-cols-[auto_1fr] items-start gap-x-4 gap-y-3 overflow-hidden rounded-none border border-[color:var(--tone-border)] px-6 py-5 text-sm text-[color:var(--tone-body)] shadow-[var(--glass-shadow-outline)] backdrop-blur-[12px] transition-colors",
  "before:absolute before:left-0 before:top-3 before:bottom-3 before:w-[3px] before:rounded-full before:bg-[color:var(--tone-bar)] before:content-['']",
  "after:absolute after:inset-x-0 after:top-0 after:h-px after:bg-[image:var(--tone-gradient)] after:bg-no-repeat after:bg-[length:100%_100%] after:content-['']",
);

const toastVariants = {
  default: toneVarOverrides.default,
  info: toneVarOverrides.info,
  success: toneVarOverrides.success,
  warning: toneVarOverrides.warning,
  error: toneVarOverrides.destructive,
  loading: toneVarOverrides.default,
  action: toneVarOverrides.default,
  normal: toneVarOverrides.default,
};

const toastTitleClass = cn(
  "col-start-2 font-mono text-[10px] uppercase tracking-[0.32em] text-[color:var(--tone-title)]",
);

const toastDescriptionClass = cn(
  "col-start-2 grid justify-items-start gap-2 text-left text-sm text-[color:var(--tone-description)] [&_p]:leading-relaxed",
);

const toastCloseButtonClass = cn(
  "text-muted-foreground/70 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
);

const toastCancelButtonClass = cn(
  "rounded-none border border-border/60 bg-muted/40 px-2 py-1 font-mono text-[10px] uppercase tracking-[0.28em] text-muted-foreground/70 transition-colors hover:border-foreground/60 hover:text-foreground",
);

const toastActionButtonClass = cn(
  "rounded-none border border-foreground bg-foreground px-2 py-1 font-mono text-[10px] uppercase tracking-[0.28em] text-background transition-colors hover:bg-foreground/90",
);

const toastToneCSS = `
[data-sonner-toaster] [data-sonner-toast][data-type] [data-description] {
  color: var(--tone-description);
}
[data-sonner-toaster] [data-sonner-toast][data-type] [data-title] {
  color: var(--tone-title);
}
[data-sonner-toaster] [data-sonner-toast] [data-icon] {
  grid-column-start: 1;
  grid-row: span 2 / span 2;
  margin-top: 0.25rem;
  display: flex;
  width: 1.25rem;
  height: 1.25rem;
  align-items: center;
  justify-content: center;
  border-radius: 9999px;
  border: 1px solid var(--tone-icon-border);
  background-color: var(--tone-icon-bg);
  padding: 0.25rem;
  color: var(--tone-icon-fg);
}
[data-sonner-toaster] [data-sonner-toast] [data-content] {
  grid-column-start: 2;
  display: grid;
  justify-items: start;
  gap: 0.5rem;
  text-align: left;
}
[data-sonner-toaster] [data-sonner-toast] [data-button][data-cancel],
[data-sonner-toaster] [data-sonner-toast] [data-button]:not([data-cancel]) {
  grid-column-start: 2;
}
`;

function useResolvedTheme(): () => "light" | "dark" | "system" {
  const initial =
    typeof document !== "undefined"
      ? document.documentElement.classList.contains("dark")
        ? ("dark" as const)
        : ("light" as const)
      : ("system" as const);
  const [theme, setTheme] = createSignal<"light" | "dark" | "system">(initial);

  createEffect(() => {
    if (typeof document === "undefined") return;

    const detect = () => {
      setTheme(document.documentElement.classList.contains("dark") ? "dark" : "light");
    };

    const observer = new MutationObserver(detect);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
    onCleanup(() => observer.disconnect());
  });

  return theme;
}

const Toaster: Component<ToasterProps> = (props) => {
  const [local, rest] = splitProps(props, ["theme", "class", "style", "icons", "toastOptions"]);
  const resolvedTheme = useResolvedTheme();
  const toastIcons = () => ({
    success: (<CheckCheck class="size-3.5" />) as unknown as JSX.Element,
    info: (<Info class="size-3.5" />) as unknown as JSX.Element,
    warning: (<TriangleAlert class="size-3.5" />) as unknown as JSX.Element,
    error: (<TriangleAlert class="size-3.5" />) as unknown as JSX.Element,
  });

  const userClasses = () => local.toastOptions?.classes ?? {};

  return (
    <>
      <style nonce={getCspNonce()}>{toastToneCSS}</style>
      <Sonner
        theme={local.theme ?? resolvedTheme()}
        class={cn("toaster group", local.class)}
        style={{
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
          "--offset-top": "var(--offset, 32px)",
          "--offset-right": "var(--offset, 32px)",
          "--offset-bottom": "var(--offset, 32px)",
          "--offset-left": "var(--offset, 32px)",
          ...(typeof local.style === "object" ? local.style : {}),
        }}
        icons={{ ...toastIcons(), ...local.icons }}
        toastOptions={{
          ...local.toastOptions,
          unstyled: true,
          classes: {
            toast: cn(toastBaseClass, userClasses().toast),
            title: cn(toastTitleClass, userClasses().title),
            description: cn(toastDescriptionClass, userClasses().description),
            closeButton: cn(toastCloseButtonClass, userClasses().closeButton),
            cancelButton: cn(toastCancelButtonClass, userClasses().cancelButton),
            actionButton: cn(toastActionButtonClass, userClasses().actionButton),
            default: cn(toastVariants.default, userClasses().default),
            info: cn(toastVariants.info, userClasses().info),
            success: cn(toastVariants.success, userClasses().success),
            warning: cn(toastVariants.warning, userClasses().warning),
            error: cn(toastVariants.error, userClasses().error),
            loading: cn(toastVariants.loading, userClasses().loading),
          },
        }}
        {...rest}
      />
    </>
  );
};

export { Toaster };
