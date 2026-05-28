import { createSignal, createEffect, For, Show } from "solid-js";
import type { JSX } from "solid-js";
import {
  InfoIcon,
  ShieldIcon,
  UsersIcon,
  UserIcon,
  PencilIcon,
  PuzzleIcon,
  PaletteIcon,
  LinkIcon,
  PackagePlusIcon,
} from "lucide-solid";
import { Dialog, DialogContent, DialogTitle } from "@/shared/ui/dialog";
import { Tabs, TabsList, TabsTrigger } from "@/shared/ui/tabs";
import { AboutSection } from "../sections/AboutSection";
import { SecuritySection } from "../sections/SecuritySection";
import { WorkspaceSection } from "../sections/WorkspaceSection";
import { AccountSection } from "../sections/AccountSection";
import { EditorSection } from "../sections/EditorSection";
import { CorePluginsSection } from "../sections/CorePluginsSection";
import { ThemeSection } from "../sections/ThemeSection";
import { ExternalAccessSection } from "../sections/ExternalAccessSection";
import { workspaceManager } from "@/features/panel";
import { CommunityPluginsSection } from "@/features/plugin-management";
import {
  getDefaultPluginHostCredentialStore,
  listPluginRuntimeApplications,
  purgePluginApplicationLocalData,
  requestPluginRuntimeApplicationsRefresh,
  submitPluginConsentDecision,
} from "@/features/plugin-runtime";

type TabEntry = { id: string; label: string; icon: () => JSX.Element };

const optionsTabs: TabEntry[] = [
  { id: "about", label: "About", icon: () => <InfoIcon class="size-4" /> },
  { id: "editor", label: "Editor", icon: () => <PencilIcon class="size-4" /> },
  { id: "theme", label: "Appearance", icon: () => <PaletteIcon class="size-4" /> },
  { id: "core-plugins", label: "Core Plugins", icon: () => <PuzzleIcon class="size-4" /> },
];

const managementTabs: TabEntry[] = [
  { id: "workspace", label: "Workspace", icon: () => <UsersIcon class="size-4" /> },
  {
    id: "community-plugins",
    label: "Community Plugins",
    icon: () => <PackagePlusIcon class="size-4" />,
  },
  { id: "external-access", label: "External", icon: () => <LinkIcon class="size-4" /> },
  { id: "security", label: "Security", icon: () => <ShieldIcon class="size-4" /> },
  { id: "account", label: "Account", icon: () => <UserIcon class="size-4" /> },
];

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialTab?: string;
  closePluginRuntimeByApplication?: (
    applicationId: string,
    reason?: string,
  ) => void | Promise<void>;
  beginPluginRuntimeApplicationRevocation?: (applicationId: string) => void;
  releasePluginRuntimeApplicationRevocation?: (applicationId: string) => void;
  closePluginRuntimeByWorkspace?: (workspaceId: string, reason?: string) => void | Promise<void>;
  releasePluginRuntimeWorkspaceRevocation?: (workspaceId: string) => void;
}

function TabButton(props: { tab: TabEntry }) {
  return (
    <TabsTrigger
      value={props.tab.id}
      class="h-auto w-full flex-none justify-start gap-3 border-0 px-3 py-2 text-sm normal-case tracking-normal data-[selected]:bg-foreground data-[selected]:text-background"
    >
      <span class="shrink-0">{props.tab.icon()}</span>
      <span class="min-w-0 truncate whitespace-nowrap">{props.tab.label}</span>
    </TabsTrigger>
  );
}

export function SettingsDialog(props: SettingsDialogProps) {
  const [activeTab, setActiveTab] = createSignal(props.initialTab ?? "about");
  const pluginTabs = workspaceManager.getSettingTabs();

  let prevPluginTabId: string | null = null;
  let prevOpen = false;
  let prevInitialTab = props.initialTab ?? "about";

  createEffect(() => {
    const open = props.open;
    const initialTab = props.initialTab ?? "about";
    if (open && (!prevOpen || initialTab !== prevInitialTab)) {
      setActiveTab(initialTab);
    }
    prevOpen = open;
    prevInitialTab = initialTab;
  });

  createEffect(() => {
    const current = activeTab();
    const tabs = pluginTabs();
    if (prevPluginTabId && prevPluginTabId !== current) {
      const prevTab = tabs.find((t) => `plugin:${t.id}` === prevPluginTabId);
      prevTab?.hide();
    }
    prevPluginTabId = current.startsWith("plugin:") ? current : null;
  });

  createEffect(() => {
    if (!props.open && prevPluginTabId) {
      const tabs = pluginTabs();
      const tab = tabs.find((t) => `plugin:${t.id}` === prevPluginTabId);
      tab?.hide();
      prevPluginTabId = null;
    }
  });

  const pluginTabEntries = () =>
    pluginTabs().map((t) => ({
      id: `plugin:${t.id}`,
      label: t.name,
      icon: () => <PuzzleIcon class="size-4" />,
    }));

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent class="max-w-5xl h-[70vh] flex flex-col p-0 gap-0" showCloseButton={true}>
        <DialogTitle class="sr-only">Settings</DialogTitle>
        <Tabs
          value={activeTab()}
          onChange={setActiveTab}
          orientation="vertical"
          class="min-h-0 flex-1 gap-0"
        >
          <div class="flex flex-1 min-h-0">
            <div class="w-48 border-r border-border/60 py-4 shrink-0 overflow-y-auto">
              <h2 class="px-4 mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Options
              </h2>
              <TabsList
                aria-label="Settings"
                class="flex h-auto w-full flex-col items-stretch justify-start gap-1 border-0 bg-transparent px-2"
              >
                <For each={optionsTabs}>{(tab) => <TabButton tab={tab} />}</For>
                <For each={pluginTabEntries()}>{(tab) => <TabButton tab={tab} />}</For>
              </TabsList>

              <h2 class="px-4 mt-6 mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
                Management
              </h2>
              <TabsList
                aria-label="Management"
                class="flex h-auto w-full flex-col items-stretch justify-start gap-1 border-0 bg-transparent px-2"
              >
                <For each={managementTabs}>{(tab) => <TabButton tab={tab} />}</For>
              </TabsList>
            </div>

            <div class="flex-1 min-h-0 overflow-y-auto">
              <Show when={activeTab() === "about"}>
                <AboutSection />
              </Show>
              <Show when={activeTab() === "editor"}>
                <EditorSection />
              </Show>
              <Show when={activeTab() === "theme"}>
                <ThemeSection />
              </Show>
              <Show when={activeTab() === "workspace"}>
                <WorkspaceSection
                  closePluginRuntimeByWorkspace={props.closePluginRuntimeByWorkspace}
                  releasePluginRuntimeWorkspaceRevocation={
                    props.releasePluginRuntimeWorkspaceRevocation
                  }
                />
              </Show>
              <Show when={activeTab() === "community-plugins"}>
                <CommunityPluginsSection
                  purgeLocalData={purgePluginApplicationLocalData}
                  listRuntimeApplications={listPluginRuntimeApplications}
                  requestRuntimeApplicationsRefresh={requestPluginRuntimeApplicationsRefresh}
                  beginRuntimeApplicationRevocation={props.beginPluginRuntimeApplicationRevocation}
                  closeRuntimeByApplication={props.closePluginRuntimeByApplication}
                  releaseRuntimeApplicationRevocation={
                    props.releasePluginRuntimeApplicationRevocation
                  }
                  storeCredential={(registration) =>
                    getDefaultPluginHostCredentialStore().storeCredential(registration)
                  }
                  submitConsentDecision={submitPluginConsentDecision}
                />
              </Show>
              <Show when={activeTab() === "external-access"}>
                <ExternalAccessSection />
              </Show>
              <Show when={activeTab() === "security"}>
                <SecuritySection />
              </Show>
              <Show when={activeTab() === "account"}>
                <AccountSection />
              </Show>
              <Show when={activeTab() === "core-plugins"}>
                <CorePluginsSection />
              </Show>
              <For each={pluginTabs()}>
                {(tab) => (
                  <Show when={activeTab() === `plugin:${tab.id}`}>
                    <div
                      ref={(el) => {
                        el.appendChild(tab.containerEl);
                        tab.display();
                      }}
                      class="p-6"
                    />
                  </Show>
                )}
              </For>
            </div>
          </div>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
