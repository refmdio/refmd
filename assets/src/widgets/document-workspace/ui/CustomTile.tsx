import type { MosaicBranch } from "solid-mosaic-component";
import { MosaicWindow } from "solid-mosaic-component";
import { workspaceManager, type usePanelWorkspace } from "@/features/panel";

type Workspace = ReturnType<typeof usePanelWorkspace>;

interface CustomTileProps {
  panelId: string;
  path: MosaicBranch[];
  workspace: Workspace;
}

export function CustomTile(props: CustomTileProps) {
  const leaf = () => workspaceManager.getLeafById(props.panelId);

  return (
    <MosaicWindow<string>
      title={leaf()?.getDisplayText() ?? ""}
      path={props.path}
      onDragStart={() => props.workspace.focusPanel(props.panelId)}
      toolbarControls={<div />}
    >
      <div
        class="h-full"
        data-panel-id={props.panelId}
        onFocusIn={() => props.workspace.focusPanel(props.panelId)}
        onMouseDown={() => props.workspace.focusPanel(props.panelId)}
        ref={(el) => {
          const currentLeaf = leaf();
          if (currentLeaf?.view?.containerEl && !el.contains(currentLeaf.view.containerEl)) {
            el.appendChild(currentLeaf.view.containerEl);
          }
        }}
      />
    </MosaicWindow>
  );
}
