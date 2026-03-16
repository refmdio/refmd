import { splitProps, type ParentProps, type JSX } from "solid-js";

import { cn } from "@/shared/lib/utils";

function ScrollArea(props: ParentProps<{ class?: string } & JSX.HTMLAttributes<HTMLDivElement>>) {
  const [local, rest] = splitProps(props, ["class", "children"]);
  return (
    <div data-slot="scroll-area" class={cn("relative overflow-hidden", local.class)} {...rest}>
      <div
        data-slot="scroll-area-viewport"
        class="size-full overflow-auto rounded-[inherit] focus-visible:ring-ring/50 transition-[color,box-shadow] outline-none focus-visible:ring-[3px] focus-visible:outline-1 [&::-webkit-scrollbar]:w-2.5 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb]:bg-border [&::-webkit-scrollbar-thumb]:border-l [&::-webkit-scrollbar-thumb]:border-l-transparent"
      >
        {local.children}
      </div>
    </div>
  );
}

function ScrollBar(
  props: ParentProps<
    {
      class?: string;
      orientation?: "vertical" | "horizontal";
    } & JSX.HTMLAttributes<HTMLDivElement>
  >,
) {
  const [local, rest] = splitProps(props, ["class", "orientation"]);
  const orientation = () => local.orientation ?? "vertical";
  return (
    <div
      data-slot="scroll-area-scrollbar"
      data-orientation={orientation()}
      class={cn(
        "flex touch-none p-px transition-colors select-none",
        orientation() === "vertical" && "h-full w-2.5 border-l border-l-transparent",
        orientation() === "horizontal" && "h-2.5 flex-col border-t border-t-transparent",
        local.class,
      )}
      {...rest}
    >
      <div data-slot="scroll-area-thumb" class="bg-border relative flex-1 rounded-full" />
    </div>
  );
}

export { ScrollArea, ScrollBar };
