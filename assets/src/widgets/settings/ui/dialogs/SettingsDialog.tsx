import { createSignal, createEffect, For, Show } from "solid-js";
import type { JSX } from "solid-js";
import { cn } from "@/shared/lib/utils";
import {
  InfoIcon,
  ShieldIcon,
  UsersIcon,
  UserIcon,
  PencilIcon,
  PuzzleIcon,
  PaletteIcon,
} from "lucide-solid";
import { Dialog, DialogContent, DialogTitle } from "@/shared/ui/dialog";
import { AboutSection } from "../sections/AboutSection";
import { SecuritySection } from "../sections/SecuritySection";
import { WorkspaceSection } from "../sections/WorkspaceSection";
import { AccountSection } from "../sections/AccountSection";
import { EditorSection } from "../sections/EditorSection";
import { CorePluginsSection } from "../sections/CorePluginsSection";
import { ThemeSection } from "../sections/ThemeSection";
import { workspaceManager } from "@/features/panel";

type TabEntry = { id: string; label: string; icon: () => JSX.Element };

const optionsTabs: TabEntry[] = [
  { id: "about", label: "About", icon: () => <InfoIcon class="size-4" /> },
  { id: "editor", label: "Editor", icon: () => <PencilIcon class="size-4" /> },
  { id: "theme", label: "Appearance", icon: () => <PaletteIcon class="size-4" /> },
  { id: "core-plugins", label: "Core Plugins", icon: () => <PuzzleIcon class="size-4" /> },
];

const managementTabs: TabEntry[] = [
  { id: "workspace", label: "Workspace", icon: () => <UsersIcon class="size-4" /> },
  { id: "security", label: "Security", icon: () => <ShieldIcon class="size-4" /> },
  { id: "account", label: "Account", icon: () => <UserIcon class="size-4" /> },
];

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function TabButton(props: { tab: TabEntry; active: boolean; onClick: () => void }) {
  return (
    <button
      role="tab"
      aria-selected={props.active}
      onClick={props.onClick}
      class={cn(
        "w-full flex items-center gap-3 px-3 py-2 text-sm transition-colors",
        props.active
          ? "bg-foreground text-background"
          : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
      )}
    >
      {props.tab.icon()}
      {props.tab.label}
    </button>
  );
}

export function SettingsDialog(props: SettingsDialogProps) {
  const [activeTab, setActiveTab] = createSignal("about");
  const pluginTabs = workspaceManager.getSettingTabs();

  let prevPluginTabId: string | null = null;
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
        <div class="flex flex-1 min-h-0">
          <div class="w-48 border-r border-border/60 py-4 shrink-0 overflow-y-auto">
            <h2 class="px-4 mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Options
            </h2>
            <nav role="tablist" aria-label="Settings" class="space-y-1 px-2">
              <For each={optionsTabs}>
                {(tab) => (
                  <TabButton
                    tab={tab}
                    active={activeTab() === tab.id}
                    onClick={() => setActiveTab(tab.id)}
                  />
                )}
              </For>
              <For each={pluginTabEntries()}>
                {(tab) => (
                  <TabButton
                    tab={tab}
                    active={activeTab() === tab.id}
                    onClick={() => setActiveTab(tab.id)}
                  />
                )}
              </For>
            </nav>

            <h2 class="px-4 mt-6 mb-3 font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Management
            </h2>
            <nav role="tablist" aria-label="Management" class="space-y-1 px-2">
              <For each={managementTabs}>
                {(tab) => (
                  <TabButton
                    tab={tab}
                    active={activeTab() === tab.id}
                    onClick={() => setActiveTab(tab.id)}
                  />
                )}
              </For>
            </nav>
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
              <WorkspaceSection />
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
      </DialogContent>
    </Dialog>
  );
}
