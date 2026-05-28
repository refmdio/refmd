import type { WorkspaceTileConfig } from "@/shared/lib/workspace/app";
import type {
  PluginEditorContributionEntry,
  PluginUiRegistryEntry,
  PluginUiResourceContext,
} from "@/features/plugin-runtime";

export function createDocumentPluginResourceContext(args: {
  workspaceId?: string | null;
  documentId: string;
  selectionPresent: boolean;
  capabilities: readonly string[];
}): PluginUiResourceContext | null {
  if (!args.workspaceId) return null;

  return {
    resourceKind: "document",
    workspaceId: args.workspaceId,
    documentId: args.documentId,
    documentOpen: true,
    selectionPresent: args.selectionPresent,
    capabilities: args.capabilities,
  };
}

export function createWorkspaceTilePluginResourceContext(args: {
  workspaceId?: string | null;
  documentId: string;
  selectionPresent: boolean;
}): Parameters<NonNullable<WorkspaceTileConfig["isAvailable"]>>[0] | null {
  if (!args.workspaceId) return null;

  return {
    resourceKind: "document",
    workspaceId: args.workspaceId,
    documentId: args.documentId,
    documentOpen: true,
    selectionPresent: args.selectionPresent,
  };
}

export function pluginEditorContributionMatchesWorkspace(
  entry: PluginEditorContributionEntry,
  workspaceId?: string | null,
): boolean {
  return Boolean(workspaceId && entry.owner.workspaceId === workspaceId);
}

export function pluginUiEntryResourceContext(
  entry: PluginUiRegistryEntry,
  args: {
    workspaceId?: string | null;
    documentId: string;
    selectionPresent: boolean;
  },
): PluginUiResourceContext | null {
  return createDocumentPluginResourceContext({
    ...args,
    capabilities: entry.capabilities,
  });
}
