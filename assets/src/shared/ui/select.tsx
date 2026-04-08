import { splitProps, type ComponentProps, type JSX, type ParentProps } from "solid-js";
import * as SelectPrimitive from "@kobalte/core/select";
import { CheckIcon, ChevronDownIcon, ChevronUpIcon } from "lucide-solid";

import { glassSurfaceSubtleClass } from "@/shared/lib/glass";
import { useOptionalFormControlProps } from "@/shared/lib/form-control";
import { cn } from "@/shared/lib/utils";

function Select<Option, OptGroup = never>(
  props: SelectPrimitive.SelectRootProps<Option, OptGroup> & { children?: JSX.Element },
) {
  return <SelectPrimitive.Root data-slot="select" {...props} />;
}

function SelectValue(
  props: Omit<ComponentProps<typeof SelectPrimitive.Value>, "children"> & {
    children?: JSX.Element | ((state: unknown) => JSX.Element);
  },
) {
  return (
    <SelectPrimitive.Value
      data-slot="select-value"
      {...(props as ComponentProps<typeof SelectPrimitive.Value>)}
    />
  );
}

function SelectTrigger(
  props: ComponentProps<typeof SelectPrimitive.Trigger> & {
    size?: "sm" | "default";
  },
) {
  const [local, rest] = splitProps(props, [
    "class",
    "children",
    "size",
    "id",
    "aria-describedby",
    "aria-invalid",
  ]);
  const formControlProps = useOptionalFormControlProps();
  const size = () => local.size ?? "default";
  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      data-size={size()}
      id={local.id ?? formControlProps?.().id}
      aria-describedby={local["aria-describedby"] ?? formControlProps?.()["aria-describedby"]}
      aria-invalid={local["aria-invalid"] ?? formControlProps?.()["aria-invalid"]}
      class={cn(
        "flex w-fit items-center justify-between gap-2 px-3 py-2 text-sm whitespace-nowrap text-foreground/90 data-[placeholder]:text-muted-foreground/70 [&_svg:not([class*='text-'])]:text-muted-foreground/70 transition-[border,background,color,box-shadow] outline-none disabled:cursor-not-allowed disabled:opacity-50 data-[size=default]:h-10 data-[size=sm]:h-9",
        glassSurfaceSubtleClass,
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

function SelectContent(
  props: ComponentProps<typeof SelectPrimitive.Content> & {
    position?: "popper" | "item-aligned";
    align?: "start" | "center" | "end";
  },
) {
  const [local, rest] = splitProps(props, ["class", "children", "position", "align"]);
  const position = () => local.position ?? "popper";
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        class={cn(
          "relative z-50 max-h-[var(--kb-popper-content-available-height)] min-w-[8rem] origin-[var(--kb-select-content-transform-origin)] overflow-x-hidden overflow-y-auto",
          glassSurfaceSubtleClass,
          "data-[expanded]:animate-in data-[closed]:animate-out data-[closed]:fade-out-0 data-[expanded]:fade-in-0 data-[closed]:zoom-out-95 data-[expanded]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
          position() === "popper" &&
            "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
          local.class,
        )}
        {...rest}
      >
        <SelectScrollUpButton />
        <SelectPrimitive.Listbox
          class={cn(
            "p-1",
            position() === "popper" && "w-full min-w-[var(--kb-select-trigger-width)] scroll-my-1",
          )}
        >
          {local.children}
        </SelectPrimitive.Listbox>
        <SelectScrollDownButton />
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

function SelectGroup(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class"]);
  return <div data-slot="select-group" role="group" class={local.class} {...rest} />;
}

function SelectLabel(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
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

function scrollSelectList(target: EventTarget | null, direction: "up" | "down") {
  if (!(target instanceof HTMLElement)) return;
  const content = target.closest("[data-slot='select-content']");
  const listbox = content?.querySelector("[role='listbox']");
  if (!(listbox instanceof HTMLElement)) return;

  listbox.scrollBy({
    top: direction === "up" ? -40 : 40,
  });
}

function SelectItem(props: ComponentProps<typeof SelectPrimitive.Item>) {
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

function SelectScrollUpButton(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>,
) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div
      data-slot="select-scroll-up-button"
      class={cn("flex cursor-default items-center justify-center py-1", local.class)}
      onMouseDown={(event: MouseEvent) => event.preventDefault()}
      onClick={(event: MouseEvent) => scrollSelectList(event.currentTarget as HTMLDivElement, "up")}
      {...rest}
    >
      {local.children ?? <ChevronUpIcon class="size-4" />}
    </div>
  );
}

function SelectScrollDownButton(
  props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>,
) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div
      data-slot="select-scroll-down-button"
      class={cn("flex cursor-default items-center justify-center py-1", local.class)}
      onMouseDown={(event: MouseEvent) => event.preventDefault()}
      onClick={(event: MouseEvent) =>
        scrollSelectList(event.currentTarget as HTMLDivElement, "down")
      }
      {...rest}
    >
      {local.children ?? <ChevronDownIcon class="size-4" />}
    </div>
  );
}

export {
  Select,
  SelectContent,
  SelectGroup,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
  SelectItem,
};
