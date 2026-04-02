import { type JSX, splitProps } from "solid-js";
import { cn } from "@/shared/lib/utils";
function Card(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="card"
      class={cn(
        "flex flex-col rounded-none border border-border bg-card text-card-foreground",
        local.class,
      )}
      {...rest}
    />
  );
}
function CardHeader(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="card-header"
      class={cn(
        "grid auto-rows-min grid-rows-[auto_auto] items-start gap-2 px-6 py-5 has-data-[slot=card-action]:grid-cols-[1fr_auto] border-b border-border text-muted-foreground",
        local.class,
      )}
      {...rest}
    />
  );
}
function CardTitle(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="card-title"
      class={cn("leading-none font-semibold text-card-foreground", local.class)}
      {...rest}
    />
  );
}
function CardDescription(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="card-description"
      class={cn("text-muted-foreground text-sm", local.class)}
      {...rest}
    />
  );
}
function CardContent(props: JSX.HTMLAttributes<HTMLDivElement>) {
  const [local, rest] = splitProps(props, ["class"]);
  return <div data-slot="card-content" class={cn("px-6 py-6", local.class)} {...rest} />;
}
export { Card, CardHeader, CardTitle, CardDescription, CardContent };
