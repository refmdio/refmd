export { attachActiveLeafRouteSync } from "./lib/manager/active-leaf-route-sync";
export { closeWorkspaceTiles } from "./lib/workspace/close-document-panels";
export {
  createMountedShareWorkspaceTileTarget,
  createShareLinkWorkspaceTileTarget,
  decodePanelId,
  decodeWorkspacePluginTileId,
  hasScrollGroupPeer,
} from "./lib/workspace/panel-utils";
export {
  disposePanelWorkspace,
  retainPanelWorkspace,
  usePanelWorkspace,
} from "./model/workspace/use-panel-workspace";
export { workspaceManager } from "./lib/manager/workspace-manager";
