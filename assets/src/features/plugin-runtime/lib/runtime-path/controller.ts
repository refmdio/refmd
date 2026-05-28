import type { PluginHostMessageRouter } from "../host-rpc/host-rpc";
import type { PluginRendererSlot } from "../renderer/host-renderer";
import type { CreatePluginRuntimePathOptions, PluginRuntimePath } from "./runtime-path";

export interface PluginHostRuntimeController {
  router: PluginHostMessageRouter;
  flushPendingAudit?(): Promise<void>;
  createRuntimePath(
    options: Omit<CreatePluginRuntimePathOptions, "router"> & {
      rendererSlots?: readonly PluginRendererSlot[];
    },
  ): Promise<PluginRuntimePath>;
}
