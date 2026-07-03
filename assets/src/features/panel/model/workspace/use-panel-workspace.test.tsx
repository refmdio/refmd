import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import { render } from "solid-js/web";
import { afterEach, describe, expect, it } from "vitest";
import { workspaceManager } from "../../lib/manager/workspace-manager";
import { decodePanelId, decodeWorkspacePluginTileId } from "../../lib/workspace/panel-utils";
import { closeWorkspaceTiles } from "../../lib/workspace/close-document-panels";
import {
  disposePanelWorkspace,
  retainPanelWorkspace,
  usePanelWorkspace,
} from "./use-panel-workspace";

type Workspace = ReturnType<typeof usePanelWorkspace>;

function runWithWorkspace(fn: (workspace: Workspace) => void): void {
  const root = document.createElement("div");
  document.body.append(root);
  const queryClient = new QueryClient();
  const dispose = render(
    () => (
      <QueryClientProvider client={queryClient}>
        <Harness run={fn} />
      </QueryClientProvider>
    ),
    root,
  );
  dispose();
  root.remove();
}

function Harness(props: { run: (workspace: Workspace) => void }) {
  props.run(usePanelWorkspace());
  return null;
}

function RetainHarness(props: { run: (workspace: Workspace, release: () => void) => void }) {
  const lease = retainPanelWorkspace();
  props.run(lease.workspace, lease.release);
  return null;
}

describe("panel workspace plugin actions", () => {
  afterEach(() => {
    workspaceManager.reset();
    disposePanelWorkspace();
  });

  it("uses a dedicated preview pane for document split mode", () => {
    runWithWorkspace((workspace) => {
      workspace.openDocument({ id: "document-one" });

      const panelIds = collectPanelIds(workspace.mosaicState());
      const panelTypes = panelIds.map((panelId) => decodePanelId(panelId)?.type).sort();

      expect(panelTypes).toEqual(["markdown", "preview"]);
    });
  });

  it("collapses a markdown-preview split to a real WYSIWYG pane", () => {
    runWithWorkspace((workspace) => {
      workspace.openDocument({ id: "document-one" });
      const markdownPanelId = collectPanelIds(workspace.mosaicState()).find(
        (panelId) => decodePanelId(panelId)?.type === "markdown",
      );

      expect(markdownPanelId).toBeTruthy();
      workspace.collapseSplitTo(markdownPanelId!, "wysiwyg");

      const panelIds = collectPanelIds(workspace.mosaicState());
      expect(panelIds).toHaveLength(1);
      expect(decodePanelId(panelIds[0])?.type).toBe("wysiwyg");
    });
  });

  it("rejects forged, mismatched, and consumed workspace tile actions", () => {
    runWithWorkspace((workspace) => {
      workspace.openWorkspaceTile("plugin.panel", "document-one");

      const panelId = workspace.focusedPanelId();
      expect(panelId).toBeTruthy();
      const decoded = decodeWorkspacePluginTileId(panelId!);
      expect(decoded?.actionId).toBeTruthy();

      expect(
        workspace.consumeWorkspaceTileAction(
          "wpa-forged",
          "plugin.panel",
          panelId!,
          "document-one",
        ),
      ).toBeUndefined();
      expect(
        workspace.consumeWorkspaceTileAction(
          decoded!.actionId,
          "plugin.panel",
          panelId!,
          "document-two",
        ),
      ).toBeUndefined();
      expect(
        workspace.consumeWorkspaceTileAction(
          decoded!.actionId,
          "plugin.panel",
          panelId!,
          "document-one",
        ),
      ).toBeUndefined();
    });
  });

  it("returns the issued workspace tile action once for the matching tile instance", () => {
    runWithWorkspace((workspace) => {
      workspace.openWorkspaceTile("plugin.panel", "document-one");

      const panelId = workspace.focusedPanelId();
      expect(panelId).toBeTruthy();
      const decoded = decodeWorkspacePluginTileId(panelId!);
      expect(decoded?.actionId).toBeTruthy();

      const action = workspace.consumeWorkspaceTileAction(
        decoded!.actionId,
        "plugin.panel",
        panelId!,
        "document-one",
      );
      expect(action).toMatchObject({
        actionId: decoded!.actionId,
        tileId: "plugin.panel",
        tileInstanceId: panelId,
        documentId: "document-one",
      });
      expect(
        workspace.consumeWorkspaceTileAction(
          decoded!.actionId,
          "plugin.panel",
          panelId!,
          "document-one",
        ),
      ).toBeUndefined();
    });
  });

  it("refreshes an existing workspace tile action instead of opening a duplicate", () => {
    runWithWorkspace((workspace) => {
      workspace.openWorkspaceTile("plugin.panel", "document-one");

      const firstPanelId = workspace.focusedPanelId();
      expect(firstPanelId).toBeTruthy();
      const firstDecoded = decodeWorkspacePluginTileId(firstPanelId!);
      expect(firstDecoded?.actionId).toBeTruthy();
      workspace.openWorkspaceTile("plugin.panel", "document-one");

      const secondPanelId = workspace.focusedPanelId();
      expect(secondPanelId).toBeTruthy();
      const secondDecoded = decodeWorkspacePluginTileId(secondPanelId!);
      expect(secondPanelId).not.toBe(firstPanelId);
      expect(secondDecoded).toMatchObject({
        tileId: "plugin.panel",
        documentId: "document-one",
        instanceId: firstDecoded!.instanceId,
      });
      expect(secondDecoded?.actionId).toBeTruthy();
      expect(secondDecoded?.actionId).not.toBe(firstDecoded?.actionId);
      expect(JSON.stringify(workspace.mosaicState()).match(/plugin:workspace/g)).toHaveLength(1);
      expect(JSON.stringify(workspace.mosaicState())).toContain(secondPanelId);
      expect(JSON.stringify(workspace.mosaicState())).not.toContain(firstPanelId);
      expect(
        workspace.consumeWorkspaceTileAction(
          firstDecoded!.actionId,
          "plugin.panel",
          firstPanelId!,
          "document-one",
        ),
      ).toBeUndefined();
      expect(
        workspace.consumeWorkspaceTileAction(
          secondDecoded!.actionId,
          "plugin.panel",
          secondPanelId!,
          "document-one",
        ),
      ).toMatchObject({
        actionId: secondDecoded!.actionId,
        tileId: "plugin.panel",
        tileInstanceId: secondPanelId,
        documentId: "document-one",
      });
    });
  });

  it("does not issue a new workspace tile action for plain focus", () => {
    runWithWorkspace((workspace) => {
      workspace.openWorkspaceTile("plugin.panel", "document-one");

      const panelId = workspace.focusedPanelId();
      expect(panelId).toBeTruthy();
      const decoded = decodeWorkspacePluginTileId(panelId!);
      expect(decoded?.actionId).toBeTruthy();

      workspace.focusPanel(panelId!);

      expect(workspace.focusedPanelId()).toBe(panelId);
      expect(
        workspace.consumeWorkspaceTileAction(
          decoded!.actionId,
          "plugin.panel",
          panelId!,
          "document-one",
        ),
      ).toMatchObject({
        actionId: decoded!.actionId,
        tileId: "plugin.panel",
        tileInstanceId: panelId,
        documentId: "document-one",
      });
      expect(
        workspace.consumeWorkspaceTileAction(
          decoded!.actionId,
          "plugin.panel",
          panelId!,
          "document-one",
        ),
      ).toBeUndefined();
    });
  });

  it.each(["row", "column"] as const)(
    "splits plugin workspace tiles %s with Host-issued actions for each split leaf",
    (direction) => {
      runWithWorkspace((workspace) => {
        workspace.openWorkspaceTile("plugin.panel", "document-one");

        const originalPanelId = workspace.focusedPanelId();
        expect(originalPanelId).toBeTruthy();
        const original = decodeWorkspacePluginTileId(originalPanelId!);
        expect(original?.actionId).toBeTruthy();

        workspace.splitPanel(originalPanelId!, direction);

        const state = workspace.mosaicState();
        expect(state).toMatchObject({ direction });
        const pluginPanelIds = collectPanelIds(state).filter((panelId) => {
          const decoded = decodeWorkspacePluginTileId(panelId);
          return decoded?.tileId === "plugin.panel" && decoded.documentId === "document-one";
        });
        expect(pluginPanelIds).toHaveLength(2);
        expect(pluginPanelIds).not.toContain(originalPanelId);
        expect(workspace.focusedPanelId()).toBe(pluginPanelIds[0]);

        const updated = decodeWorkspacePluginTileId(pluginPanelIds[0]);
        const sibling = decodeWorkspacePluginTileId(pluginPanelIds[1]);
        expect(updated).toMatchObject({
          tileId: "plugin.panel",
          documentId: "document-one",
          instanceId: original!.instanceId,
        });
        expect(sibling).toMatchObject({
          tileId: "plugin.panel",
          documentId: "document-one",
        });
        expect(updated?.actionId).toBeTruthy();
        expect(sibling?.actionId).toBeTruthy();
        expect(updated?.actionId).not.toBe(original?.actionId);
        expect(sibling?.actionId).not.toBe(updated?.actionId);

        expect(
          workspace.consumeWorkspaceTileAction(
            original!.actionId,
            "plugin.panel",
            originalPanelId!,
            "document-one",
          ),
        ).toBeUndefined();
        expect(
          workspace.consumeWorkspaceTileAction(
            updated!.actionId,
            "plugin.panel",
            pluginPanelIds[0],
            "document-one",
          ),
        ).toMatchObject({
          actionId: updated!.actionId,
          tileId: "plugin.panel",
          tileInstanceId: pluginPanelIds[0],
          documentId: "document-one",
        });
        expect(
          workspace.consumeWorkspaceTileAction(
            sibling!.actionId,
            "plugin.panel",
            pluginPanelIds[1],
            "document-one",
          ),
        ).toMatchObject({
          actionId: sibling!.actionId,
          tileId: "plugin.panel",
          tileInstanceId: pluginPanelIds[1],
          documentId: "document-one",
        });
      });
    },
  );

  it("closes open workspace tile panels by tile id without removing other plugin tiles", () => {
    runWithWorkspace((workspace) => {
      workspace.openWorkspaceTile("plugin.alpha", "document-one");
      workspace.openWorkspaceTile("plugin.beta", "document-one");

      expect(JSON.stringify(workspace.mosaicState())).toContain("plugin.alpha");
      expect(JSON.stringify(workspace.mosaicState())).toContain("plugin.beta");

      workspace.closeWorkspaceTiles(["plugin.alpha"]);

      const encodedState = JSON.stringify(workspace.mosaicState());
      expect(encodedState).not.toContain("plugin.alpha");
      expect(encodedState).toContain("plugin.beta");
      expect(workspace.focusedPanelId()).toContain("plugin.beta");
    });
  });

  it("closes document-bound plugin workspace tiles when the document closes", () => {
    runWithWorkspace((workspace) => {
      workspace.openDocument({ id: "document-one" });
      workspace.openWorkspaceTile("plugin.alpha", "document-one");
      const alphaPanelId = workspace.focusedPanelId();
      const alphaActionId = decodeWorkspacePluginTileId(alphaPanelId!)?.actionId;
      workspace.openWorkspaceTile("plugin.beta", "document-two");

      closeWorkspaceTiles(workspace, "document-one");

      const encodedState = JSON.stringify(workspace.mosaicState());
      expect(encodedState).not.toContain("document-one");
      expect(encodedState).not.toContain("plugin.alpha");
      expect(encodedState).toContain("plugin.beta");
      expect(
        workspace.consumeWorkspaceTileAction(
          alphaActionId,
          "plugin.alpha",
          alphaPanelId!,
          "document-one",
        ),
      ).toBeUndefined();
    });
  });

  it("closes open plugin workspace tile leaves when the tile descriptor is removed", () => {
    runWithWorkspace((workspace) => {
      workspaceManager.setMosaicOps({
        focusPanel: workspace.focusPanel,
        setMosaicState: workspace.setMosaicState,
        mosaicState: workspace.mosaicState,
        openWorkspaceTile: workspace.openWorkspaceTile,
        closeWorkspaceTiles: workspace.closeWorkspaceTiles,
      });
      workspaceManager.addWorkspaceTile({
        id: "plugin.removed",
        tileId: "plugin.removed",
        title: "Removed tile",
        scope: "document",
        preferredOpen: "document_menu",
        render: () => undefined,
      });
      workspaceManager.openWorkspaceTile("plugin.removed", "document-one");

      expect(JSON.stringify(workspace.mosaicState())).toContain("plugin.removed");

      workspaceManager.removeWorkspaceTile("plugin.removed");

      expect(JSON.stringify(workspace.mosaicState())).not.toContain("plugin.removed");
    });
  });

  it("keeps the workspace alive while overlapping root owners are retained", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const queryClient = new QueryClient();
    const releases: Array<() => void> = [];
    const workspaces: Workspace[] = [];
    const dispose = render(
      () => (
        <QueryClientProvider client={queryClient}>
          <RetainHarness
            run={(workspace, release) => {
              workspaces.push(workspace);
              releases.push(release);
            }}
          />
          <RetainHarness
            run={(workspace, release) => {
              workspaces.push(workspace);
              releases.push(release);
            }}
          />
        </QueryClientProvider>
      ),
      root,
    );

    expect(workspaces[0]).toBe(workspaces[1]);
    workspaces[0].openDocument({ id: "document-one" });
    releases[0]();
    expect(useExistingWorkspaceMosaic(workspaces[1])).not.toBeNull();
    releases[1]();
    dispose();
    root.remove();
  });
});

function useExistingWorkspaceMosaic(workspace: Workspace) {
  return workspace.mosaicState();
}

function collectPanelIds(node: ReturnType<Workspace["mosaicState"]>): string[] {
  if (!node) return [];
  if (typeof node === "string") return [node];
  return [...collectPanelIds(node.first), ...collectPanelIds(node.second)];
}
