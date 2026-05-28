import { splitProps, Show, type ComponentProps, type JSX } from "solid-js";
import * as DialogPrimitive from "@kobalte/core/dialog";
import { XIcon } from "lucide-solid";
import {
  glassCloseButtonClass,
  glassOverlayBackdropClass,
  glassSurfaceStrongClass,
} from "@/shared/lib/glass";
import { cn, omniMonoText } from "@/shared/lib/utils";

function clearStaleDialogPointerLock(): void {
  if (typeof document === "undefined") return;
  const hasVisibleDialog = document.querySelector(
    '[data-slot="dialog-content"]:not([aria-hidden="true"])',
  );
  if (hasVisibleDialog) return;
  for (const element of [document.documentElement, document.body]) {
    if (element?.style.pointerEvents === "none") {
      element.style.pointerEvents = "";
    }
  }
}

function queueDialogPointerLockCleanup(): void {
  window.setTimeout(clearStaleDialogPointerLock, 0);
  window.setTimeout(clearStaleDialogPointerLock, 250);
}

function Dialog(props: ComponentProps<typeof DialogPrimitive.Root>) {
  const [local, rest] = splitProps(props, ["onOpenChange"]);
  return (
    <DialogPrimitive.Root
      data-slot="dialog"
      onOpenChange={(open) => {
        local.onOpenChange?.(open);
        if (!open) queueDialogPointerLockCleanup();
      }}
      {...rest}
    />
  );
}

function DialogTrigger(props: ComponentProps<typeof DialogPrimitive.Trigger>) {
  return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} />;
}

function DialogPortal(props: ComponentProps<typeof DialogPrimitive.Portal>) {
  return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} />;
}

function DialogClose(props: ComponentProps<typeof DialogPrimitive.CloseButton>) {
  return <DialogPrimitive.CloseButton data-slot="dialog-close" {...props} />;
}

function DialogOverlay(props: ComponentProps<typeof DialogPrimitive.Overlay>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <DialogPrimitive.Overlay
      data-slot="dialog-overlay"
      class={cn(
        glassOverlayBackdropClass,
        "data-[expanded]:animate-in data-[expanded]:fade-in-0 data-[closed]:pointer-events-none data-[closed]:animate-out data-[closed]:fade-out-0",
        local.class,
      )}
      {...rest}
    />
  );
}

function DialogContent(
  props: ComponentProps<typeof DialogPrimitive.Content> & {
    showCloseButton?: boolean;
  },
) {
  const [local, rest] = splitProps(props, ["class", "children", "showCloseButton"]);
  const showClose = () => local.showCloseButton !== false;
  return (
    <DialogPortal>
      <DialogOverlay />
      <DialogPrimitive.Content
        data-slot="dialog-content"
        class={cn(
          "fixed left-1/2 top-1/2 z-50 grid w-full max-w-xl -translate-x-1/2 -translate-y-1/2 gap-6 px-6 py-6",
          glassSurfaceStrongClass,
          "data-[expanded]:animate-in data-[expanded]:fade-in-0 data-[expanded]:zoom-in-95 data-[closed]:animate-out data-[closed]:zoom-out-95",
          local.class,
        )}
        {...rest}
      >
        {local.children}
        <Show when={showClose()}>
          <DialogPrimitive.CloseButton data-slot="dialog-close" class={glassCloseButtonClass}>
            <XIcon class="size-4" />
            <span class="sr-only">Close</span>
          </DialogPrimitive.CloseButton>
        </Show>
      </DialogPrimitive.Content>
    </DialogPortal>
  );
}

function DialogHeader(props: JSX.HTMLAttributes<HTMLDivElement> & { class?: string }) {
  const [local, rest] = splitProps(props, ["class"]);
  return <div data-slot="dialog-header" class={cn("flex flex-col gap-3", local.class)} {...rest} />;
}

function DialogFooter(props: JSX.HTMLAttributes<HTMLDivElement> & { class?: string }) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <div
      data-slot="dialog-footer"
      class={cn(
        "flex flex-col-reverse gap-2 border-t border-border/60 pt-4 sm:flex-row sm:justify-end",
        local.class,
      )}
      {...rest}
    />
  );
}

function DialogTitle(props: ComponentProps<typeof DialogPrimitive.Title>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      class={cn(omniMonoText.section, "text-muted-foreground", local.class)}
      {...rest}
    />
  );
}

function DialogDescription(props: ComponentProps<typeof DialogPrimitive.Description>) {
  const [local, rest] = splitProps(props, ["class"]);
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      class={cn("text-sm text-foreground/80", local.class)}
      {...rest}
    />
  );
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
};
