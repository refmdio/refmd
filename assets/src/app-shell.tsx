import { Show, createEffect, createSignal, onCleanup, type ParentProps } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { Sidebar } from "@/widgets/sidebar";
import { SettingsDialog } from "@/widgets/settings";
import { currentWorkspaceId, setCurrentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { useSettings } from "@/entities/settings";
import { workspacesApi, encryptionApi, getRateLimitRetryMs } from "@/shared/api";
import { authState, deviceState, cryptoWorkerReady } from "@/shared/lib/auth-state";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { usePendingDevices, performKekRotation } from "@/features/devices";
import { attachActiveLeafRouteSync, usePanelWorkspace, workspaceManager } from "@/features/panel";
import { Button } from "@/shared/ui/button";
import { BellIcon } from "lucide-solid";
import {
  setFocusedPanelIdAccessor,
  setOnEditorRegistered,
  getActiveEditor,
  getEditorForDocument,
  getDocText,
} from "@/features/editor";
import {
  appDocuments,
  documentEvents,
  documentQueries,
  documentRuntime,
} from "@/shared/lib/document-manager";
import { documentNavigation } from "@/shared/lib/document-navigation";
import { initApp } from "@/shared/lib/app-context";
import {
  registerCorePlugins,
  loadCorePlugins,
  unloadCorePlugins,
} from "@/shared/lib/core-plugin-registry";
import { loadDocumentTree, unloadDocumentTree } from "@/core-plugins/document-tree";
import { loadCommandPalette, unloadCommandPalette } from "@/core-plugins/command-palette";
import { loadWordCount, unloadWordCount } from "@/core-plugins/word-count";
import { getStatusBarEl } from "@/widgets/document-workspace";
import { buildDocumentPath } from "@/shared/lib/document-routes";
import { createWorkspaceBridge } from "@/shared/lib/workspace-bridge";
import { Toaster } from "@/shared/ui/sonner";

const rotationAttempted = new Set<string>();

export function AppShell(props: ParentProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [settingsOpen, setSettingsOpen] = createSignal(false);

  const { workspaces, workspacesNeedingRotation } = useWorkspaces();
  const documentWorkspace = usePanelWorkspace();
  useSettings();

  // --- Plugin infrastructure initialization ---

  setFocusedPanelIdAccessor(() => documentWorkspace.focusedPanelId());
  setOnEditorRegistered(() => documentEvents.flushPendingOpens());
  documentNavigation.init((documentId) =>
    navigate(buildDocumentPath(documentId), { replace: true, scroll: false }),
  );

  documentRuntime.init(
    {
      focusedDocumentId: () => documentWorkspace.focusedDocumentId(),
    },
    queryClient,
    () => currentWorkspaceId(),
    () => getActiveEditor(),
    (docId) => getEditorForDocument(docId),
  );
  documentRuntime.setDocTextResolver((id) => getDocText(id));
  documentRuntime.setCreateDocumentFn(async (wsId, title, parentId) => {
    try {
      const { createDocument } = await import("@/features/document");
      return await createDocument(wsId, title, parentId);
    } catch (err) {
      // Only fall back to offline creation on network errors, not auth/permission errors
      if (err instanceof TypeError || (err instanceof Error && err.message.includes("fetch"))) {
        const { createDocumentOffline } = await import("@/shared/lib/offline/offline-create-sync");
        return createDocumentOffline(wsId, parentId, title);
      }
      throw err;
    }
  });

  workspaceManager.setEditorContextResolver(() => {
    const editor = getActiveEditor();
    const doc = documentQueries.getActiveDocument();
    if (!editor || !doc) return null;
    return { editor, doc };
  });
  workspaceManager.setActiveDocumentResolver(() => documentQueries.getActiveDocument());

  const app = initApp(workspaceManager, appDocuments);
  workspaceManager.setAppRef(app);
  workspaceManager.setMosaicOps({
    focusPanel: (panelId) => documentWorkspace.focusPanel(panelId),
    setMosaicState: (state) => documentWorkspace.setMosaicState(state),
    mosaicState: () => documentWorkspace.mosaicState(),
  });

  registerCorePlugins([
    {
      id: "document-tree",
      name: "Document Tree",
      description: "Browse documents and folders in the sidebar.",
      defaultEnabled: true,
      load: loadDocumentTree,
      unload: unloadDocumentTree,
    },
    {
      id: "command-palette",
      name: "Command Palette",
      description: "Quickly access commands from your keyboard.",
      defaultEnabled: true,
      load: loadCommandPalette,
      unload: unloadCommandPalette,
    },
    {
      id: "word-count",
      name: "Word Count",
      description: "Display the number of words and characters in the status bar.",
      defaultEnabled: true,
      load: loadWordCount,
      unload: unloadWordCount,
    },
  ]);

  // Centralized reactive bridges: SolidJS signals → WorkspaceManager/DocumentManager events
  createWorkspaceBridge(workspaceManager, documentEvents, {
    focusedPanelId: () => documentWorkspace.focusedPanelId(),
    openDocuments: () => documentWorkspace.openDocuments(),
    mosaicState: () => documentWorkspace.mosaicState(),
    statusBarEl: () => getStatusBarEl(),
  });

  onCleanup(attachActiveLeafRouteSync(navigate, () => documentWorkspace.openDocuments()));

  // Sync offline-created documents and start background caching
  let bgCacheCleanup: (() => void) | null = null;
  let offlineWatchCleanup: (() => void) | null = null;
  let offlineSyncTimer: ReturnType<typeof setTimeout> | null = null;
  let offlineSyncInFlight = false;
  let offlineSyncQueued = false;

  function clearOfflineSyncTimer() {
    if (offlineSyncTimer) {
      clearTimeout(offlineSyncTimer);
      offlineSyncTimer = null;
    }
  }

  async function runOfflineSync(): Promise<void> {
    const wsId = currentWorkspaceId();
    if (!wsId || !cryptoWorkerReady()) return;
    if (offlineSyncInFlight) {
      offlineSyncQueued = true;
      return;
    }

    offlineSyncInFlight = true;
    try {
      const { offlineMode: isOffline } = await import("@/shared/lib/offline/offline-state");
      if (isOffline()) return;

      const { waitForGlobalRateLimit } = await import("@/shared/api/core");
      await waitForGlobalRateLimit();

      const { syncOfflineCreatedDocuments } =
        await import("@/shared/lib/offline/offline-create-sync");
      await syncOfflineCreatedDocuments(wsId).catch(() => {});

      const { syncPendingDocuments } = await import("@/features/editor");
      await syncPendingDocuments(wsId);

      if (bgCacheCleanup) bgCacheCleanup();
      const { startBackgroundCaching } = await import("@/shared/lib/offline/background-cache");
      bgCacheCleanup = startBackgroundCaching(wsId);
    } catch (error) {
      const retryMs = getRateLimitRetryMs(error);
      if (retryMs !== null) {
        scheduleOfflineSync(retryMs);
        return;
      }
    } finally {
      offlineSyncInFlight = false;
      if (offlineSyncQueued) {
        offlineSyncQueued = false;
        scheduleOfflineSync();
      }
    }
  }

  function scheduleOfflineSync(delayMs = 3_000) {
    const wsId = currentWorkspaceId();
    if (!wsId || !cryptoWorkerReady()) return;

    clearOfflineSyncTimer();
    offlineSyncTimer = setTimeout(() => {
      offlineSyncTimer = null;
      void runOfflineSync();
    }, delayMs);
  }

  // Run on workspace/crypto ready change
  createEffect(() => {
    const wsId = currentWorkspaceId();
    if (wsId && cryptoWorkerReady()) {
      scheduleOfflineSync();

      // Also re-run on offline → online transition
      if (!offlineWatchCleanup) {
        import("@/shared/lib/offline/offline-state").then(({ onOfflineModeChange }) => {
          offlineWatchCleanup = onOfflineModeChange((isOffline) => {
            if (!isOffline) scheduleOfflineSync(1_000);
          });
        });
      }
    }
  });
  onCleanup(() => {
    clearOfflineSyncTimer();
    bgCacheCleanup?.();
    offlineWatchCleanup?.();
  });

  // Core plugin lifecycle: initial load (synchronous, before Sidebar mount)
  const initialWsId = currentWorkspaceId();
  let corePluginsLoaded = false;
  if (initialWsId) {
    loadCorePlugins(app, initialWsId);
    corePluginsLoaded = true;
  }

  function registerBuiltinCommands() {
    workspaceManager.addCommand({
      id: "editor:switch-mode",
      name: "Switch editor mode",
      editorCallback: () => {
        const pid = documentWorkspace.focusedPanelId();
        if (pid) documentWorkspace.switchPanelType(pid);
      },
    });
    workspaceManager.addCommand({
      id: "editor:split-horizontal",
      name: "Split editor horizontally",
      editorCallback: () => {
        const pid = documentWorkspace.focusedPanelId();
        if (pid) documentWorkspace.splitPanel(pid, "row");
      },
    });
    workspaceManager.addCommand({
      id: "editor:split-vertical",
      name: "Split editor vertically",
      editorCallback: () => {
        const pid = documentWorkspace.focusedPanelId();
        if (pid) documentWorkspace.splitPanel(pid, "column");
      },
    });
    workspaceManager.addCommand({
      id: "editor:close-panel",
      name: "Close current panel",
      callback: () => {
        const pid = documentWorkspace.focusedPanelId();
        if (pid) documentWorkspace.closePanel(pid);
      },
    });
    workspaceManager.addCommand({
      id: "editor:switch-to-split",
      name: "Switch to split view",
      editorCallback: () => {
        const pid = documentWorkspace.focusedPanelId();
        if (pid) documentWorkspace.switchToSplit(pid);
      },
    });
  }

  registerBuiltinCommands();

  // Workspace change: reload plugins
  let loadedForWsId: string | null = initialWsId;
  createEffect(() => {
    const wsId = currentWorkspaceId();
    if (wsId === loadedForWsId && corePluginsLoaded) return;
    if (corePluginsLoaded) {
      unloadCorePlugins();
      workspaceManager.reset();
      registerBuiltinCommands();
      corePluginsLoaded = false;
    }
    if (wsId) {
      loadCorePlugins(app, wsId);
      corePluginsLoaded = true;
      loadedForWsId = wsId;
    }
  });

  onCleanup(() => {
    if (corePluginsLoaded) {
      unloadCorePlugins();
      corePluginsLoaded = false;
    }
  });

  // --- Existing workspace logic ---

  createEffect(() => {
    const pending = workspacesNeedingRotation();
    if (pending.length === 0) return;

    const auth = authState();
    const device = deviceState();
    if (!cryptoWorkerReady() || !auth || !device?.deviceId) return;

    const initiatorWorkspaces = pending.filter(
      (ws) =>
        ws.kek_rotation_initiator_user_id === auth.user.id &&
        !rotationAttempted.has(ws.workspace_id),
    );
    if (initiatorWorkspaces.length === 0) return;

    for (const ws of initiatorWorkspaces) {
      rotationAttempted.add(ws.workspace_id);
    }

    performKekRotation(initiatorWorkspaces, auth.user.id, device.deviceId)
      .then(() => {
        for (const ws of initiatorWorkspaces) {
          rotationAttempted.delete(ws.workspace_id);
        }
        queryClient.invalidateQueries({ queryKey: ["workspaces"] });
      })
      .catch(() => {
        for (const ws of initiatorWorkspaces) {
          rotationAttempted.delete(ws.workspace_id);
        }
      });
  });

  let prevWorkspaceId: string | null = null;
  createEffect(() => {
    const wsId = currentWorkspaceId();
    if (prevWorkspaceId !== null && wsId !== prevWorkspaceId) {
      documentWorkspace.resetWorkspace();
    }
    prevWorkspaceId = wsId;
  });

  const handleSelectWorkspace = (id: string) => {
    setCurrentWorkspaceId(id);
    navigate("/dashboard");
  };

  const handleCreateWorkspace = async (data: {
    name: string;
    description?: string;
    icon?: string;
  }) => {
    const auth = authState();
    const device = deviceState();

    if (!auth?.user || !device?.deviceId || !cryptoWorkerReady()) return;

    const result = await workspacesApi.create(data);
    if (!result.id) return;

    {
      const worker = getCryptoWorker();

      const { keyVersion } = await worker.generateKek(result.id);

      const deviceEcdhPublic = device.deviceEcdhPublic!;
      const kekWrapped = await worker.encryptKekForDevice({
        workspaceId: result.id,
        userId: auth.user.id,
        senderDeviceId: device.deviceId,
        targetDeviceId: device.deviceId,
        targetDeviceEcdhPublic: deviceEcdhPublic,
        keyVersion,
      });

      await encryptionApi.createWorkspaceKeyWithPop(result.id, {
        device_id: device.deviceId,
        key_version: keyVersion,
        sender_device_id: device.deviceId,
        encrypted_kek: base64UrlEncode(kekWrapped.encrypted),
        nonce: base64UrlEncode(kekWrapped.nonce),
        is_active: true,
      });

      const kekBackup = await worker.wrapKekWithUmk({
        workspaceId: result.id,
        userId: auth.user.id,
        keyVersion,
      });

      await encryptionApi.createKekBackupWithPop(result.id, {
        key_version: keyVersion,
        encrypted_kek: base64UrlEncode(kekBackup.encrypted),
        nonce: base64UrlEncode(kekBackup.nonce),
      });
    }

    queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    setCurrentWorkspaceId(result.id);
    navigate("/dashboard");
  };

  const { pendingCount } = usePendingDevices();

  const notificationSlot = () => (
    <Show when={pendingCount() > 0}>
      <Button
        variant="ghost"
        size="icon"
        class="size-9 relative"
        onClick={() => setSettingsOpen(true)}
        aria-label="Pending device approvals"
      >
        <BellIcon class="size-4" />
        <span class="absolute -top-0.5 -right-0.5 size-4 rounded-full bg-destructive text-destructive-foreground text-[10px] flex items-center justify-center">
          {pendingCount()}
        </span>
      </Button>
    </Show>
  );

  return (
    <div class="flex h-screen">
      <Sidebar
        workspaces={workspaces()}
        currentWorkspaceId={currentWorkspaceId()}
        onSelectWorkspace={handleSelectWorkspace}
        onCreateWorkspace={handleCreateWorkspace}
        notificationSlot={notificationSlot()}
        onSettingsClick={() => setSettingsOpen(true)}
      />
      <div class="flex-1 overflow-hidden">{props.children}</div>
      <SettingsDialog open={settingsOpen()} onOpenChange={setSettingsOpen} />
      <Toaster position="bottom-right" />
    </div>
  );
}
