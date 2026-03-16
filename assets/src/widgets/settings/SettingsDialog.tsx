import { createSignal, Show } from "solid-js";
import type { JSX } from "solid-js";
import { cn } from "@/shared/lib/utils";
import { InfoIcon, ShieldIcon, UsersIcon, UserIcon, PencilIcon } from "lucide-solid";
import { Dialog, DialogContent, DialogTitle } from "@/shared/ui/dialog";
import {
  AboutSection,
  SecuritySection,
  WorkspaceSection,
  AccountSection,
  EditorSection,
} from "@/widgets/settings";

type SettingsTab = "about" | "security" | "workspace" | "editor" | "account";

const tabs: { id: SettingsTab; label: string; icon: () => JSX.Element }[] = [
  {
    id: "about",
    label: "About",
    icon: () => <InfoIcon class="size-4" />,
  },
  {
    id: "security",
    label: "Security",
    icon: () => <ShieldIcon class="size-4" />,
  },
  {
    id: "workspace",
    label: "Workspace",
    icon: () => <UsersIcon class="size-4" />,
  },
  {
    id: "editor",
    label: "Editor",
    icon: () => <PencilIcon class="size-4" />,
  },
  {
    id: "account",
    label: "Account",
    icon: () => <UserIcon class="size-4" />,
  },
];

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SettingsDialog(props: SettingsDialogProps) {
  const [activeTab, setActiveTab] = createSignal<SettingsTab>("about");

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent class="max-w-5xl h-[70vh] flex flex-col p-0 gap-0" showCloseButton={true}>
        <DialogTitle class="sr-only">Settings</DialogTitle>
        <div class="flex flex-1 min-h-0">
          <div class="w-48 border-r border-border/60 py-4 shrink-0 overflow-y-auto">
            <h2 class="px-4 mb-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Settings
            </h2>
            <nav role="tablist" aria-label="Settings" class="space-y-1 px-2">
              {tabs.map((tab) => (
                <button
                  role="tab"
                  aria-selected={activeTab() === tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  class={cn(
                    "w-full flex items-center gap-3 px-3 py-2 text-sm transition-colors",
                    activeTab() === tab.id
                      ? "bg-foreground text-background"
                      : "text-muted-foreground hover:bg-muted/50 hover:text-foreground",
                  )}
                >
                  {tab.icon()}
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>

          <div class="flex-1 min-h-0 overflow-y-auto">
            <Show when={activeTab() === "about"}>
              <AboutSection />
            </Show>
            <Show when={activeTab() === "security"}>
              <SecuritySection />
            </Show>
            <Show when={activeTab() === "workspace"}>
              <WorkspaceSection />
            </Show>
            <Show when={activeTab() === "editor"}>
              <EditorSection />
            </Show>
            <Show when={activeTab() === "account"}>
              <AccountSection />
            </Show>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
