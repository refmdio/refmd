import { splitProps, type ParentProps, type JSX } from "solid-js";
import * as SelectPrimitive from "@kobalte/core/select";
import { CheckIcon, ChevronDownIcon } from "lucide-solid";

import { cn } from "@/shared/lib/utils";

function Select(props: any) {
  return <SelectPrimitive.Root data-slot="select" {...props} />;
}

function SelectValue(props: { class?: string; children?: any; [key: string]: any }) {
  return <SelectPrimitive.Value data-slot="select-value" {...props} />;
}

function SelectTrigger(
  props: ParentProps<{ class?: string; size?: "sm" | "default"; [key: string]: any }>,
) {
  const [local, rest] = splitProps(props, ["class", "children", "size"]);
  const size = () => local.size ?? "default";
  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      data-size={size()}
      class={cn(
        "border border-border/60 bg-muted/60 text-foreground/90 data-[placeholder]:text-muted-foreground/70 [&_svg:not([class*='text-'])]:text-muted-foreground/70 transition-[border,background,color,box-shadow] outline-none flex w-fit items-center justify-between gap-2 px-3 py-2 text-sm whitespace-nowrap shadow-[var(--glass-shadow-outline-subtle)] backdrop-blur-[2px] disabled:cursor-not-allowed disabled:opacity-50 data-[size=default]:h-10 data-[size=sm]:h-9 rounded-none",
        "focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        "aria-invalid:border-destructive aria-invalid:focus-visible:ring-destructive/30 dark:aria-invalid:focus-visible:ring-destructive/40",
        local.class,
      )}
      {...rest}
    >
      {local.children}
      <SelectPrimitive.Icon>
        <ChevronDownIcon class="size-4 opacity-50" />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}

function SelectContent(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        class={cn(
          "relative z-50 max-h-[var(--kb-popper-content-available-height)] min-w-[8rem] origin-[var(--kb-select-content-transform-origin)] overflow-x-hidden overflow-y-auto border border-border/60 bg-muted/65 text-foreground shadow-[var(--glass-shadow-outline-subtle)] backdrop-blur-[4px]",
          "data-[expanded]:animate-in data-[closed]:animate-out data-[closed]:fade-out-0 data-[expanded]:fade-in-0 data-[closed]:zoom-out-95 data-[expanded]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
          "rounded-none",
          local.class,
        )}
        {...rest}
      >
        <SelectPrimitive.Listbox class="p-1" />
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

function SelectGroup(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class"]);
  return <div data-slot="select-group" role="group" class={local.class} {...rest} />;
}

function SelectGroupLabel(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>,
) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="select-label"
      class={cn(
        "px-3 py-2 font-mono text-[10px] uppercase tracking-[0.28em] text-muted-foreground/90",
        local.class,
      )}
      {...rest}
    />
  );
}

function SelectItem(props: ParentProps<{ class?: string; item: any; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <SelectPrimitive.Item
      data-slot="select-item"
      class={cn(
        "relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/90 outline-hidden select-none transition-[background,color]",
        "data-[disabled]:pointer-events-none data-[disabled]:opacity-40",
        "hover:bg-foreground hover:text-background",
        "data-[highlighted]:bg-foreground data-[highlighted]:text-background",
        "data-[selected]:bg-foreground data-[selected]:text-background",
        "rounded-none",
        local.class,
      )}
      {...rest}
    >
      <span class="absolute right-2 flex size-3.5 items-center justify-center">
        <SelectPrimitive.ItemIndicator>
          <CheckIcon class="size-4" />
        </SelectPrimitive.ItemIndicator>
      </span>
      <SelectPrimitive.ItemLabel>{local.children}</SelectPrimitive.ItemLabel>
    </SelectPrimitive.Item>
  );
}

function SelectSeparator(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>,
) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="select-separator"
      role="separator"
      class={cn(
        "pointer-events-none -mx-1 my-1 h-px bg-gradient-to-r from-transparent via-border/60 to-transparent",
        local.class,
      )}
      {...rest}
    />
  );
}

function SelectDescription(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <SelectPrimitive.Description
      data-slot="select-description"
      class={cn("text-sm text-muted-foreground", local.class)}
      {...rest}
    />
  );
}

function SelectErrorMessage(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <SelectPrimitive.ErrorMessage
      data-slot="select-error-message"
      class={cn("text-sm text-destructive", local.class)}
      {...rest}
    />
  );
}

export {
  Select,
  SelectContent,
  SelectGroup,
  SelectGroupLabel,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
  SelectDescription,
  SelectErrorMessage,
};
