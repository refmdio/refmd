export { usePanelWorkspace } from "./model/use-panel-workspace";
export type { OpenDocument } from "./model/use-panel-workspace";
export { attachActiveLeafRouteSync } from "./lib/active-leaf-route-sync";
export { closeDocumentPanels } from "./lib/close-document-panels";
export {
  encodePanelId,
  decodePanelId,
  findFirstDocumentId,
  findFirstPanelId,
  hasDocumentPanels,
  hasDocumentPanelOfType,
  hasScrollGroupPeer,
} from "./lib/panel-utils";
export type { PanelType, PanelId } from "./lib/panel-utils";
export { workspaceManager, WorkspaceManagerImpl } from "./lib/workspace-manager";
export type { Command, Hotkey, SidebarPanelConfig } from "@/shared/lib/app-context";
