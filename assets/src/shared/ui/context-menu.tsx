import { splitProps, type ParentProps, type JSX } from "solid-js";
import * as ContextMenuPrimitive from "@kobalte/core/context-menu";
import { CheckIcon, ChevronRightIcon, CircleIcon } from "lucide-solid";

import { cn } from "@/shared/lib/utils";

function ContextMenu(props: ParentProps<{ [key: string]: any }>) {
  return <ContextMenuPrimitive.Root data-slot="context-menu" {...props} />;
}

function ContextMenuTrigger(props: ParentProps<{ class?: string; [key: string]: any }>) {
  return <ContextMenuPrimitive.Trigger data-slot="context-menu-trigger" {...props} />;
}

function ContextMenuGroup(props: ParentProps<{ class?: string; [key: string]: any }>) {
  return <ContextMenuPrimitive.Group data-slot="context-menu-group" {...props} />;
}

function ContextMenuPortal(props: ParentProps & { [key: string]: any }) {
  return <ContextMenuPrimitive.Portal {...props}>{props.children}</ContextMenuPrimitive.Portal>;
}

function ContextMenuSub(props: ParentProps<{ [key: string]: any }>) {
  return <ContextMenuPrimitive.Sub data-slot="context-menu-sub" {...props} />;
}

function ContextMenuRadioGroup(props: ParentProps<{ class?: string; [key: string]: any }>) {
  return <ContextMenuPrimitive.RadioGroup data-slot="context-menu-radio-group" {...props} />;
}

const itemBase =
  "relative flex cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color] data-[disabled]:pointer-events-none data-[disabled]:opacity-40 rounded-none";

function ContextMenuSubTrigger(
  props: ParentProps<{ class?: string; inset?: boolean; [key: string]: any }>,
) {
  const [local, rest] = splitProps(props, ["class", "inset", "children"]);
  return (
    <ContextMenuPrimitive.SubTrigger
      data-slot="context-menu-sub-trigger"
      data-inset={local.inset}
      class={cn(
        itemBase,
        "hover:bg-foreground hover:text-background",
        local.inset && "pl-9",
        local.class,
      )}
      {...rest}
    >
      {local.children}
      <ChevronRightIcon class="ml-auto size-4" />
    </ContextMenuPrimitive.SubTrigger>
  );
}

function ContextMenuSubContent(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <ContextMenuPrimitive.SubContent
      data-slot="context-menu-sub-content"
      class={cn(
        "z-50 min-w-[10rem] origin-[var(--kb-menu-content-transform-origin)] overflow-hidden border border-border/60 bg-muted/60 p-1 text-foreground shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]",
        "data-[expanded]:animate-in data-[expanded]:fade-in-0 data-[expanded]:zoom-in-95 data-[closed]:animate-out data-[closed]:zoom-out-95",
        "rounded-none",
        local.class,
      )}
      {...rest}
    />
  );
}

function ContextMenuContent(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <ContextMenuPrimitive.Portal>
      <ContextMenuPrimitive.Content
        data-slot="context-menu-content"
        class={cn(
          "z-50 max-h-[var(--kb-popper-content-available-height)] min-w-[10rem] origin-[var(--kb-menu-content-transform-origin)] overflow-hidden border border-border/60 bg-muted/60 p-1 text-foreground shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]",
          "data-[expanded]:animate-in data-[expanded]:fade-in-0 data-[expanded]:zoom-in-95 data-[closed]:animate-out data-[closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
          "rounded-none",
          local.class,
        )}
        {...rest}
      />
    </ContextMenuPrimitive.Portal>
  );
}

function ContextMenuItem(
  props: ParentProps<{
    class?: string;
    inset?: boolean;
    variant?: "default" | "destructive";
    [key: string]: any;
  }>,
) {
  const [local, rest] = splitProps(props, ["class", "inset", "variant"]);
  const variant = () => local.variant ?? "default";
  return (
    <ContextMenuPrimitive.Item
      data-slot="context-menu-item"
      data-inset={local.inset}
      data-variant={variant()}
      class={cn(
        itemBase,
        "hover:bg-foreground hover:text-background",
        variant() === "destructive" &&
          "text-destructive hover:bg-destructive hover:text-background",
        local.inset && "pl-9",
        local.class,
      )}
      {...rest}
    />
  );
}

function ContextMenuCheckboxItem(
  props: ParentProps<{ class?: string; checked?: boolean; [key: string]: any }>,
) {
  const [local, rest] = splitProps(props, ["class", "children", "checked"]);
  return (
    <ContextMenuPrimitive.CheckboxItem
      data-slot="context-menu-checkbox-item"
      class={cn(itemBase, "pl-9 hover:bg-foreground hover:text-background", local.class)}
      checked={local.checked}
      {...rest}
    >
      <span class="pointer-events-none absolute left-3 flex size-3.5 items-center justify-center text-foreground">
        <ContextMenuPrimitive.ItemIndicator>
          <CheckIcon class="size-3.5" />
        </ContextMenuPrimitive.ItemIndicator>
      </span>
      {local.children}
    </ContextMenuPrimitive.CheckboxItem>
  );
}

function ContextMenuRadioItem(
  props: ParentProps<{ class?: string; value: string; [key: string]: any }>,
) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <ContextMenuPrimitive.RadioItem
      data-slot="context-menu-radio-item"
      class={cn(itemBase, "pl-9 hover:bg-foreground hover:text-background", local.class)}
      {...rest}
    >
      <span class="pointer-events-none absolute left-3 flex size-3.5 items-center justify-center text-foreground">
        <ContextMenuPrimitive.ItemIndicator>
          <CircleIcon class="size-2 fill-current" />
        </ContextMenuPrimitive.ItemIndicator>
      </span>
      {local.children}
    </ContextMenuPrimitive.RadioItem>
  );
}

function ContextMenuLabel(
  props: ParentProps<{ class?: string; inset?: boolean } & JSX.HTMLAttributes<HTMLDivElement>>,
) {
  const [local, rest] = splitProps(props, ["class", "inset"]);
  return (
    <div
      data-slot="context-menu-label"
      data-inset={local.inset}
      class={cn(
        "px-3 py-2 font-mono text-[10px] uppercase tracking-[0.32em] text-muted-foreground/70",
        local.inset && "pl-9",
        local.class,
      )}
      {...rest}
    />
  );
}

function ContextMenuSeparator(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <ContextMenuPrimitive.Separator
      data-slot="context-menu-separator"
      class={cn(
        "pointer-events-none -mx-1 my-1 h-px bg-gradient-to-r from-transparent via-border/60 to-transparent",
        local.class,
      )}
      {...rest}
    />
  );
}

function ContextMenuShortcut(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLSpanElement>>,
) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <span
      data-slot="context-menu-shortcut"
      class={cn(
        "ml-auto font-mono text-[10px] uppercase tracking-[0.32em] text-muted-foreground/70",
        local.class,
      )}
      {...rest}
    />
  );
}

export {
  ContextMenu,
  ContextMenuTrigger,
  ContextMenuGroup,
  ContextMenuPortal,
  ContextMenuSub,
  ContextMenuRadioGroup,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuLabel,
  ContextMenuCheckboxItem,
  ContextMenuRadioItem,
  ContextMenuSubTrigger,
  ContextMenuSubContent,
  ContextMenuShortcut,
};
