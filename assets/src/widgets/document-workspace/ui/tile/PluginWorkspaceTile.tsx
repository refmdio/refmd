import { For, Show, createEffect, createMemo, createSignal, onCleanup } from "solid-js";
import type { MosaicBranch } from "solid-mosaic-component";
import { MosaicWindow } from "solid-mosaic-component";
import { Columns2Icon, MoreVerticalIcon, RefreshCcwIcon, SplitIcon, XIcon } from "lucide-solid";
import {
  decodeWorkspacePluginTileId,
  workspaceManager,
  type usePanelWorkspace,
} from "@/features/panel";
import type { WorkspaceTileActionConfig } from "@/shared/lib/workspace/app";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";

type Workspace = ReturnType<typeof usePanelWorkspace>;
type WorkspaceTileActionPlacement = WorkspaceTileActionConfig["placement"];

const WORKSPACE_TILE_ACTION_ORDER_MIN = -10_000;
const WORKSPACE_TILE_ACTION_ORDER_MAX = 10_000;

interface PluginWorkspaceTileProps {
  panelId: string;
  path: MosaicBranch[];
  workspace: Workspace;
}

export function PluginWorkspaceTile(props: PluginWorkspaceTileProps) {
  const [container, setContainer] = createSignal<HTMLDivElement>();
  const decoded = () => decodeWorkspacePluginTileId(props.panelId);
  const panelWorkspaceId = () => {
    const target = decoded();
    if (!target) return undefined;
    return workspaceManager.getWorkspaceTiles().find((entry) => entry.id === target.tileId)?.owner
      ?.workspaceId;
  };
  const availabilityContext = () => {
    const target = decoded();
    if (target?.documentId) {
      return {
        resourceKind: "document" as const,
        workspaceId: panelWorkspaceId(),
        documentId: target.documentId,
        documentOpen: true,
        selectionPresent: false,
      };
    }
    return {
      resourceKind: "workspace" as const,
      workspaceId: panelWorkspaceId(),
      documentOpen: false,
      selectionPresent: false,
    };
  };
  const panel = createMemo(() => {
    const target = decoded();
    if (!target) return null;
    const entry = workspaceManager
      .getWorkspaceTiles()
      .find((candidate) => candidate.id === target.tileId);
    if (!entry) return null;
    if (!(entry.isAvailable?.(availabilityContext()) ?? true)) return null;
    return entry;
  });
  const renderContext = () => {
    const target = decoded();
    return {
      tileInstanceId: props.panelId,
      documentId: target?.documentId,
    };
  };
  const renderContextWithAction = () => {
    const target = decoded();
    const action = target
      ? props.workspace.consumeWorkspaceTileAction(
          target.actionId,
          target.tileId,
          props.panelId,
          target.documentId,
        )
      : undefined;
    return {
      ...renderContext(),
      action,
    };
  };
  const actions = createMemo(() => panel()?.actions?.() ?? []);
  const actionsByPlacement = (placement: WorkspaceTileActionPlacement) =>
    createMemo(() =>
      actions()
        .filter((action) => action.placement === placement)
        .sort(compareWorkspaceTileAction),
    );
  const refreshActions = actionsByPlacement("refresh");
  const toolbarActions = actionsByPlacement("tile_toolbar");
  const menuActions = actionsByPlacement("tile_menu");
  const invokeWorkspaceTileAction = async (action: WorkspaceTileActionConfig) => {
    const entry = panel();
    if (!entry) return;
    try {
      const allowed = await entry.open?.(availabilityContext());
      if (allowed === false) return;
    } catch {
      return;
    }
    props.workspace.invokeWorkspaceTileAction(props.panelId, {
      tileActionId: action.actionId,
      ...(action.documentQuery ? { documentQuery: action.documentQuery } : {}),
    });
  };
  const splitWorkspaceTile = async (direction: "row" | "column") => {
    const entry = panel();
    if (!entry) return;
    try {
      const allowed = await entry.open?.(availabilityContext());
      if (allowed === false) return;
    } catch {
      return;
    }
    props.workspace.splitPanel(props.panelId, direction);
  };
  let renderedKey: string | null = null;
  let hideRenderedPanel: (() => void) | undefined;

  createEffect(() => {
    const entry = panel();
    const el = container();
    if (!entry) {
      hideRenderedPanel?.();
      hideRenderedPanel = undefined;
      renderedKey = null;
      return;
    }
    if (!el) return;
    const nextRenderedKey = `${entry.id}:${props.panelId}`;
    if (renderedKey === nextRenderedKey) return;
    hideRenderedPanel?.();
    const context = renderContextWithAction();
    renderedKey = nextRenderedKey;
    hideRenderedPanel = () => entry.hide?.(context);
    entry.render(el, context);
  });

  onCleanup(() => {
    hideRenderedPanel?.();
  });

  return (
    <MosaicWindow<string>
      title={panel()?.title ?? ""}
      path={props.path}
      onDragStart={() => props.workspace.focusPanel(props.panelId)}
      toolbarControls={
        <div class="flex items-center gap-1">
          <For each={refreshActions()}>
            {(action) => (
              <button
                type="button"
                class="p-1 hover:bg-muted rounded"
                title={action.title}
                aria-label={action.title}
                data-workspace-tile-action={action.id}
                data-workspace-tile-action-placement={action.placement}
                onClick={(event) => {
                  event.stopPropagation();
                  void invokeWorkspaceTileAction(action);
                }}
              >
                <RefreshCcwIcon class="size-4" />
              </button>
            )}
          </For>
          <For each={toolbarActions()}>
            {(action) => (
              <button
                type="button"
                class="max-w-40 truncate whitespace-nowrap rounded px-2 py-1 text-xs hover:bg-muted"
                title={action.title}
                aria-label={action.title}
                data-workspace-tile-action={action.id}
                data-workspace-tile-action-placement={action.placement}
                onClick={(event) => {
                  event.stopPropagation();
                  void invokeWorkspaceTileAction(action);
                }}
              >
                {action.title}
              </button>
            )}
          </For>
          <DropdownMenu>
            <DropdownMenuTrigger
              as="button"
              class="p-1 hover:bg-muted rounded"
              onClick={(event: MouseEvent) => event.stopPropagation()}
            >
              <MoreVerticalIcon class="size-4" />
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <For each={menuActions()}>
                {(action) => (
                  <DropdownMenuItem
                    data-workspace-tile-action={action.id}
                    data-workspace-tile-action-placement={action.placement}
                    onClick={() => void invokeWorkspaceTileAction(action)}
                  >
                    <RefreshCcwIcon class="size-4 mr-2" />
                    {action.title}
                  </DropdownMenuItem>
                )}
              </For>
              <Show when={menuActions().length > 0}>
                <DropdownMenuSeparator />
              </Show>
              <DropdownMenuItem onClick={() => void splitWorkspaceTile("row")}>
                <Columns2Icon class="size-4 mr-2" />
                Split Horizontal
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => void splitWorkspaceTile("column")}>
                <SplitIcon class="size-4 mr-2" />
                Split Vertical
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => props.workspace.closePanel(props.panelId)}>
                <XIcon class="size-4 mr-2" />
                Close
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      }
    >
      <Show
        when={panel()}
        fallback={
          <div class="flex h-full items-center justify-center text-sm text-muted-foreground" />
        }
      >
        <div
          class="h-full"
          data-panel-id={props.panelId}
          onFocusIn={() => props.workspace.focusPanel(props.panelId)}
          onMouseDown={() => props.workspace.focusPanel(props.panelId)}
          ref={(el) => setContainer(el)}
        />
      </Show>
    </MosaicWindow>
  );
}

function compareWorkspaceTileAction(
  a: WorkspaceTileActionConfig,
  b: WorkspaceTileActionConfig,
): number {
  return (
    workspaceTileActionOrder(a) - workspaceTileActionOrder(b) ||
    a.id.localeCompare(b.id) ||
    a.actionId.localeCompare(b.actionId) ||
    a.title.localeCompare(b.title)
  );
}

function workspaceTileActionOrder(action: WorkspaceTileActionConfig): number {
  const order = action.order ?? 0;
  if (!Number.isSafeInteger(order)) return 0;
  return Math.min(
    WORKSPACE_TILE_ACTION_ORDER_MAX,
    Math.max(WORKSPACE_TILE_ACTION_ORDER_MIN, order),
  );
}
