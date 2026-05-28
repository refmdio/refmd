import { For, Show, createEffect, getOwner, onCleanup } from "solid-js";
import { XIcon } from "lucide-solid";
import { workspaceManager } from "@/features/panel";
import { withPluginRenderOwner } from "@/features/plugin-runtime";
import type {
  AuxiliaryPaneActionConfig,
  AuxiliaryPaneConfig,
  AuxiliaryPaneLocation,
} from "@/shared/lib/workspace/app";

const AUXILIARY_PANE_MIN_WIDTH = 240;
const AUXILIARY_PANE_MAX_WIDTH = 480;

export function AuxiliaryPaneColumn(props: {
  panes: AuxiliaryPaneConfig[];
  location: AuxiliaryPaneLocation;
  focusedPaneId: string | null;
  setFocusedPaneId: (paneId: string) => void;
  width?: number;
  setWidth: (width: number) => void;
}) {
  let asideRef: HTMLElement | undefined;
  const width = () => {
    const configuredWidth = props.width ?? props.panes[0]?.defaultWidth ?? 320;
    return `${clampAuxiliaryPaneWidth(configuredWidth)}px`;
  };
  const resizeHandleSide = () =>
    props.location === "left" || props.location === "document_left" ? "right" : "left";

  const startResize = (event: PointerEvent) => {
    const startX = event.clientX;
    const measuredWidth = asideRef?.getBoundingClientRect().width ?? 0;
    const startWidth =
      measuredWidth > 0
        ? measuredWidth
        : clampAuxiliaryPaneWidth(props.width ?? props.panes[0]?.defaultWidth ?? 320);
    const direction = resizeHandleSide() === "right" ? 1 : -1;

    const onPointerMove = (moveEvent: PointerEvent) => {
      props.setWidth(startWidth + (moveEvent.clientX - startX) * direction);
    };
    const onPointerUp = () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
    };

    event.preventDefault();
    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", onPointerUp, { once: true });
  };

  return (
    <Show when={props.panes.length > 0}>
      <aside
        ref={(element) => {
          asideRef = element;
        }}
        class="relative flex h-full shrink-0 flex-col bg-background"
        classList={{
          "border-r border-border": props.location === "left" || props.location === "document_left",
          "border-l border-border":
            props.location === "right" || props.location === "document_right",
        }}
        style={{ width: width() }}
        data-auxiliary-pane-location={props.location}
      >
        <button
          type="button"
          aria-label="Resize auxiliary pane"
          class="absolute top-0 z-10 h-full w-1 cursor-col-resize bg-transparent hover:bg-primary/30 focus-visible:bg-primary/40 focus-visible:outline-none"
          classList={{
            "-right-0.5": resizeHandleSide() === "right",
            "-left-0.5": resizeHandleSide() === "left",
          }}
          onPointerDown={startResize}
          data-auxiliary-pane-resize-handle={props.location}
        />
        <For each={props.panes}>
          {(pane) => (
            <section
              class="flex min-h-0 flex-1 flex-col border-b border-border last:border-b-0"
              classList={{
                "ring-1 ring-primary/60": props.focusedPaneId === pane.id,
              }}
              tabIndex={-1}
              onFocusIn={() => props.setFocusedPaneId(pane.id)}
              onPointerDown={() => props.setFocusedPaneId(pane.id)}
              data-auxiliary-pane-focused={props.focusedPaneId === pane.id ? "true" : "false"}
            >
              <div class="flex h-9 shrink-0 items-center gap-2 border-b border-border px-3 text-sm font-medium">
                <span class="truncate">{pane.title}</span>
                <div class="ml-auto flex shrink-0 items-center gap-1">
                  <For each={sortedAuxiliaryPaneActions(pane.actions)}>
                    {(action) => (
                      <button
                        type="button"
                        class="inline-flex h-6 max-w-28 items-center rounded px-2 text-xs font-medium hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
                        aria-label={action.title}
                        disabled={action.isAvailable?.() === false}
                        onClick={(event) => {
                          event.stopPropagation();
                          action.invoke();
                        }}
                        data-auxiliary-pane-action={action.id}
                      >
                        <span class="truncate">{action.title}</span>
                      </button>
                    )}
                  </For>
                  <button
                    type="button"
                    class="inline-flex size-6 items-center justify-center rounded hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label={`Close ${pane.title}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      if (pane.close) {
                        pane.close();
                      } else {
                        workspaceManager.removeAuxiliaryPane(pane.id);
                      }
                    }}
                    data-auxiliary-pane-close={pane.id}
                  >
                    <XIcon class="size-4" />
                  </button>
                </div>
              </div>
              <AuxiliaryPaneFrame pane={pane} />
            </section>
          )}
        </For>
      </aside>
    </Show>
  );
}

function AuxiliaryPaneFrame(props: { pane: AuxiliaryPaneConfig }) {
  const pluginOwner = getOwner();
  let containerRef: HTMLDivElement | undefined;

  createEffect(() => {
    const pane = props.pane;
    const container = containerRef;
    if (!container) return;
    container.replaceChildren();
    withPluginRenderOwner(pluginOwner, () => pane.render(container));

    onCleanup(() => {
      pane.hide?.();
      container.replaceChildren();
    });
  });

  return (
    <div
      ref={(element) => {
        containerRef = element;
      }}
      class="min-h-0 flex-1 overflow-hidden"
      data-auxiliary-pane-id={props.pane.id}
    />
  );
}

function clampAuxiliaryPaneWidth(width: number): number {
  return Math.min(AUXILIARY_PANE_MAX_WIDTH, Math.max(AUXILIARY_PANE_MIN_WIDTH, width));
}

function sortedAuxiliaryPaneActions(
  actions: AuxiliaryPaneActionConfig[] | undefined,
): AuxiliaryPaneActionConfig[] {
  return [...(actions ?? [])].sort((first, second) => {
    const order = (first.order ?? 0) - (second.order ?? 0);
    if (order !== 0) return order;
    return first.title.localeCompare(second.title);
  });
}
