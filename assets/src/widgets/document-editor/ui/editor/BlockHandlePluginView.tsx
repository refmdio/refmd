import { createSignal, onCleanup } from "solid-js";
import { GripVertical, Plus } from "lucide-solid";
import type { SolidPluginViewUserOptions } from "@prosemirror-adapter/solid";
import type { PluginView } from "prosemirror-state";
import type { EditorView } from "prosemirror-view";
import { Button } from "@/shared/ui/button";
import type {
  BlockHandlePluginViewFactory,
  BlockHandleViewController,
  BlockHandleViewState,
} from "../../lib/prosemirror/plugin-block-handle";

type SolidPluginViewFactory = (
  options: SolidPluginViewUserOptions,
) => (view: EditorView) => PluginView;

interface BlockHandlePluginChromeProps {
  controller: BlockHandleViewController;
}

function BlockHandlePluginChrome(props: BlockHandlePluginChromeProps) {
  const [state, setState] = createSignal<BlockHandleViewState>(props.controller.getState());
  const unsubscribe = props.controller.subscribe(setState);

  onCleanup(() => {
    unsubscribe();
    props.controller.attachHandleElement(null);
  });

  return (
    <div
      ref={(element) => props.controller.attachHandleElement(element)}
      class="pm-block-handle"
      classList={{
        dragging: state().dragging,
        visible: state().visible,
      }}
      data-refmd-editor-chrome="block-handle"
      style={{
        height: `${state().height}px`,
        left: `${state().left}px`,
        top: `${state().top}px`,
      }}
      onFocusIn={() => {
        props.controller.setMenuFrozen(true);
        props.controller.refreshVisibleHandle();
      }}
      onFocusOut={() => {
        queueMicrotask(() => props.controller.setMenuFrozen(false));
      }}
      onMouseEnter={() => props.controller.setMenuFrozen(true)}
      onMouseLeave={() => props.controller.setMenuFrozen(false)}
    >
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        class="pm-block-handle-add border-0 bg-transparent p-0 normal-case tracking-normal"
        aria-label="Open block menu below"
        title="Open block menu below"
        onMouseDown={(event) => event.preventDefault()}
        onClick={(event) => props.controller.openBlockMenu(event)}
      >
        <Plus size={13} strokeWidth={2} aria-hidden="true" />
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        class="pm-block-handle-drag border-0 bg-transparent p-0 normal-case tracking-normal"
        aria-label="Drag to move block"
        title="Drag to move"
        draggable={false}
        onMouseDown={(event) => props.controller.beginMouseDrag(event)}
        onPointerDown={(event) => {
          if (event.pointerType === "mouse" || event.pointerType === "") return;
          props.controller.beginPointerDrag(event);
        }}
      >
        <GripVertical size={13} strokeWidth={2.1} aria-hidden="true" />
      </Button>
      <span class="pm-block-handle-bridge" aria-hidden="true" />
    </div>
  );
}

export function createSolidBlockHandlePluginView(
  pluginViewFactory: SolidPluginViewFactory,
): BlockHandlePluginViewFactory {
  return (view, controller) =>
    pluginViewFactory({
      component: () => <BlockHandlePluginChrome controller={controller} />,
      destroy: () => controller.attachHandleElement(null),
      root: (viewDom) => viewDom.parentElement ?? document.body,
    })(view);
}
