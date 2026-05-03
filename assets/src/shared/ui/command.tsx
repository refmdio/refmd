import type { Component, ComponentProps, ParentProps, VoidProps } from "solid-js";
import { splitProps } from "solid-js";

import type { DialogRootProps } from "@kobalte/core/dialog";
import * as CommandPrimitive from "cmdk-solid";
import { SearchIcon } from "lucide-solid";

import { glassInsetSurfaceClass } from "@/shared/lib/glass";
import { cn } from "@/shared/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";

const Command: Component<ParentProps<CommandPrimitive.CommandRootProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <CommandPrimitive.CommandRoot
      data-slot="command"
      class={cn(
        "flex h-full w-full flex-col overflow-hidden text-foreground backdrop-blur-[10px]",
        glassInsetSurfaceClass,
        local.class,
      )}
      {...others}
    />
  );
};

const CommandDialog: Component<
  ParentProps<DialogRootProps & { title?: string; description?: string }>
> = (props) => {
  const [local, others] = splitProps(props, ["children", "title", "description"]);
  return (
    <Dialog {...others}>
      <DialogHeader class="sr-only">
        <DialogTitle>{local.title ?? "Command Palette"}</DialogTitle>
        <DialogDescription>
          {local.description ?? "Search for a command to run..."}
        </DialogDescription>
      </DialogHeader>
      <DialogContent
        class={cn(
          "overflow-hidden border border-border/60 bg-muted/30 p-0 text-foreground shadow-[var(--glass-shadow-outline-heavy)] backdrop-blur-[12px]",
          "rounded-none",
        )}
      >
        <Command class="[&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.28em] [&_[cmdk-group]]:px-2 [&_[cmdk-group]:not([hidden])_~[cmdk-group]]:pt-0 [&_[cmdk-input-wrapper]_svg]:size-4 [&_[cmdk-input]]:h-12 [&_[cmdk-item]]:px-3 [&_[cmdk-item]]:py-2 [&_[cmdk-item]_svg]:size-4">
          {local.children}
        </Command>
      </DialogContent>
    </Dialog>
  );
};

const CommandInput: Component<VoidProps<CommandPrimitive.CommandInputProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="command-input-wrapper"
      class="flex h-12 items-center gap-3 border-b border-border/60 bg-muted/40 px-3"
    >
      <SearchIcon class="size-4 shrink-0 opacity-50" />
      <CommandPrimitive.CommandInput
        data-slot="command-input"
        class={cn(
          "flex h-full w-full bg-transparent font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-40",
          local.class,
        )}
        {...others}
      />
    </div>
  );
};

const CommandList: Component<ParentProps<CommandPrimitive.CommandListProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <CommandPrimitive.CommandList
      data-slot="command-list"
      class={cn("max-h-[320px] scroll-py-1 overflow-x-hidden overflow-y-auto", local.class)}
      {...others}
    />
  );
};

const CommandEmpty: Component<ParentProps<CommandPrimitive.CommandEmptyProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <CommandPrimitive.CommandEmpty
      data-slot="command-empty"
      class={cn("py-6 text-center text-sm text-muted-foreground", local.class)}
      {...others}
    />
  );
};

const CommandGroup: Component<ParentProps<CommandPrimitive.CommandGroupProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <CommandPrimitive.CommandGroup
      data-slot="command-group"
      class={cn("overflow-hidden p-1 text-foreground", local.class)}
      {...others}
    />
  );
};

const CommandSeparator: Component<VoidProps<CommandPrimitive.CommandSeparatorProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <CommandPrimitive.CommandSeparator
      data-slot="command-separator"
      class={cn(
        "pointer-events-none -mx-1 my-1 h-px bg-gradient-to-r from-transparent via-border/60 to-transparent",
        local.class,
      )}
      {...others}
    />
  );
};

const CommandItem: Component<ParentProps<CommandPrimitive.CommandItemProps>> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <CommandPrimitive.CommandItem
      data-slot="command-item"
      cmdk-item=""
      class={cn(
        "relative flex cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color]",
        "data-[selected=true]:bg-foreground data-[selected=true]:text-background",
        "data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-40",
        "rounded-none",
        local.class,
      )}
      {...others}
    />
  );
};

const CommandShortcut: Component<ComponentProps<"span">> = (props) => {
  const [local, others] = splitProps(props, ["class"]);
  return (
    <span
      data-slot="command-shortcut"
      class={cn(
        "ml-auto font-mono text-[10px] uppercase tracking-[0.32em] text-muted-foreground/70",
        local.class,
      )}
      {...others}
    />
  );
};

export {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
  CommandSeparator,
};
