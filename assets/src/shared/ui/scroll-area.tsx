import { splitProps, type ParentProps, type JSX } from "solid-js";
import { cn } from "@/shared/lib/utils";
function ScrollArea(
  props: ParentProps<
    {
      class?: string;
    } & JSX.HTMLAttributes<HTMLDivElement>
  >,
) {
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
export { ScrollArea };
