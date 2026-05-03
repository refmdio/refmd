import { splitProps, type ComponentProps } from "solid-js";
import * as TabsPrimitive from "@kobalte/core/tabs";
import { cn } from "@/shared/lib/utils";

function Tabs(props: ComponentProps<typeof TabsPrimitive.Root>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <TabsPrimitive.Root data-slot="tabs" class={cn("flex flex-col gap-2", local.class)} {...rest} />
  );
}

function TabsList(props: ComponentProps<typeof TabsPrimitive.List>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <TabsPrimitive.List
      data-slot="tabs-list"
      class={cn(
        "inline-flex h-10 w-fit items-center justify-center border border-border/60 bg-muted/30",
        local.class,
      )}
      {...rest}
    />
  );
}

function TabsTrigger(props: ComponentProps<typeof TabsPrimitive.Trigger>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      class={cn(
        "inline-flex h-10 flex-1 items-center justify-center gap-2 px-3 font-mono text-[10px] uppercase tracking-[0.28em] text-muted-foreground/90 transition-[border,background,color,box-shadow] outline-none",
        "border border-transparent rounded-none",
        "focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        "data-[selected]:border-foreground data-[selected]:bg-foreground data-[selected]:text-background",
        "disabled:pointer-events-none disabled:opacity-40",
        local.class,
      )}
      {...rest}
    />
  );
}

function TabsContent(props: ComponentProps<typeof TabsPrimitive.Content>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <TabsPrimitive.Content
      data-slot="tabs-content"
      class={cn("flex-1 outline-none", local.class)}
      {...rest}
    />
  );
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
