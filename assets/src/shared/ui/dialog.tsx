import { splitProps, Show, type ParentProps } from "solid-js"
import * as DialogPrimitive from "@kobalte/core/dialog"
import { XIcon } from "lucide-solid"
import { cn } from "@/shared/lib/utils"

function Dialog(props: ParentProps<{ [key: string]: any }>) {
  return <DialogPrimitive.Root data-slot="dialog" {...props} />
}

function DialogTrigger(props: ParentProps<{ [key: string]: any }>) {
  return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} />
}

function DialogPortal(props: ParentProps) {
  return <DialogPrimitive.Portal>{props.children}</DialogPrimitive.Portal>
}

function DialogClose(props: ParentProps<{ [key: string]: any }>) {
  return <DialogPrimitive.CloseButton data-slot="dialog-close" {...props} />
}

function DialogOverlay(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"])
  return (
    <DialogPrimitive.Overlay
      data-slot="dialog-overlay"
      class={cn(
        "fixed inset-0 z-50 bg-background/70 backdrop-blur-md transition-opacity",
        "data-[expanded]:animate-in data-[expanded]:fade-in-0 data-[closed]:animate-out data-[closed]:fade-out-0",
        local.class
      )}
      {...rest}
    />
  )
}

function DialogContent(props: ParentProps<{ class?: string; showCloseButton?: boolean; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class", "children", "showCloseButton"])
  const showClose = () => local.showCloseButton !== false
  return (
    <DialogPortal>
      <DialogOverlay />
      <DialogPrimitive.Content
        data-slot="dialog-content"
        class={cn(
          "fixed left-1/2 top-1/2 z-50 grid w-full max-w-xl -translate-x-1/2 -translate-y-1/2 gap-6 border border-border/60 bg-muted/60 px-6 py-6 text-foreground shadow-[var(--glass-shadow-outline-strong)] backdrop-blur-[8px]",
          "data-[expanded]:animate-in data-[expanded]:fade-in-0 data-[expanded]:zoom-in-95 data-[closed]:animate-out data-[closed]:zoom-out-95",
          "rounded-none",
          local.class
        )}
        {...rest}
      >
        {local.children}
        <Show when={showClose()}>
          <DialogPrimitive.CloseButton
            data-slot="dialog-close"
            class="absolute top-4 right-4 inline-flex size-9 items-center justify-center border border-border/60 bg-muted/50 text-muted-foreground/80 transition-colors focus-visible:border-foreground focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:ring-offset-2 focus-visible:ring-offset-background hover:bg-foreground hover:text-background disabled:pointer-events-none disabled:opacity-40"
          >
            <XIcon class="size-4" />
            <span class="sr-only">Close</span>
          </DialogPrimitive.CloseButton>
        </Show>
      </DialogPrimitive.Content>
    </DialogPortal>
  )
}

function DialogHeader(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"])
  return (
    <div
      data-slot="dialog-header"
      class={cn("flex flex-col gap-3", local.class)}
      {...rest}
    />
  )
}

function DialogFooter(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"])
  return (
    <div
      data-slot="dialog-footer"
      class={cn(
        "flex flex-col-reverse gap-2 border-t border-border/60 pt-4 sm:flex-row sm:justify-end",
        local.class
      )}
      {...rest}
    />
  )
}

function DialogTitle(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"])
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      class={cn(
        "font-mono text-xs uppercase tracking-[0.32em] text-muted-foreground",
        local.class
      )}
      {...rest}
    />
  )
}

function DialogDescription(props: ParentProps<{ class?: string; [key: string]: any }>) {
  const [local, rest] = splitProps(props, ["class"])
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      class={cn("text-sm text-foreground/80", local.class)}
      {...rest}
    />
  )
}

export {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
}
