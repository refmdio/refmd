import { splitProps, type ParentProps } from "solid-js";
import * as RadioGroupPrimitive from "@kobalte/core/radio-group";
import { CircleIcon } from "lucide-solid";
import { cn } from "@/shared/lib/utils";

function RadioGroup(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <RadioGroupPrimitive.Root
      data-slot="radio-group"
      class={cn("grid gap-3", local.class)}
      {...rest}
    />
  );
}

function RadioGroupItem(props: ParentProps<{ class?: string; value: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class", "children", "value", "id"]);
  return (
    <RadioGroupPrimitive.Item value={local.value} {...rest}>
      <RadioGroupPrimitive.ItemInput id={local.id} />
      <RadioGroupPrimitive.ItemControl
        data-slot="radio-group-item"
        class={cn(
          "flex aspect-square size-4 shrink-0 items-center justify-center rounded-full border border-border/60 bg-muted/40 text-foreground/80 shadow-[var(--glass-shadow-inset)] transition-[border,background,color,box-shadow] outline-none",
          "focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background",
          "aria-invalid:border-destructive aria-invalid:focus-visible:ring-destructive/30 dark:aria-invalid:focus-visible:ring-destructive/40",
          "data-[checked]:border-foreground",
          "disabled:cursor-not-allowed disabled:opacity-40",
          local.class,
        )}
      >
        <RadioGroupPrimitive.ItemIndicator
          data-slot="radio-group-indicator"
          class="flex items-center justify-center"
        >
          <CircleIcon class="size-2 fill-foreground text-foreground" />
        </RadioGroupPrimitive.ItemIndicator>
      </RadioGroupPrimitive.ItemControl>
      {local.children}
    </RadioGroupPrimitive.Item>
  );
}

export { RadioGroup, RadioGroupItem };
