import { type JSX, splitProps } from "solid-js";

import { cn, omniMonoText } from "@/shared/lib/utils";

function Label(props: JSX.LabelHTMLAttributes<HTMLLabelElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <label
      data-slot="label"
      class={cn(
        "flex items-center gap-2 text-muted-foreground/90 transition-colors select-none peer-disabled:cursor-not-allowed peer-disabled:opacity-50 group-data-[disabled=true]:pointer-events-none group-data-[disabled=true]:opacity-50 group-data-[invalid=true]:text-destructive",
        omniMonoText.base,
        local.class,
      )}
      {...rest}
    />
  );
}

export { Label };
