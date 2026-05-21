import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { Portal } from "solid-js/web";
import type { EditorView } from "prosemirror-view";
import { computePosition, offset, flip, shift } from "@floating-ui/dom";
import {
  Type,
  Heading1,
  Heading2,
  Heading3,
  List,
  ListOrdered,
  Quote,
  Code,
  Minus,
} from "lucide-solid";
import type { LucideProps } from "lucide-solid";
import type { Component } from "solid-js";
import { Command, CommandGroup, CommandItem, CommandList } from "@/shared/ui/command";
import { Tabs, TabsList, TabsTrigger } from "@/shared/ui/tabs";
import {
  CATEGORY_LABELS,
  CATEGORY_ORDER,
  type SlashCommand,
  type SlashMenuState,
  type SlashCommandCategory,
} from "../../lib/prosemirror/plugin-slash-commands";

const ICON_MAP: Record<string, Component<LucideProps>> = {
  type: Type,
  "heading-1": Heading1,
  "heading-2": Heading2,
  "heading-3": Heading3,
  list: List,
  "list-ordered": ListOrdered,
  quote: Quote,
  code: Code,
  minus: Minus,
};

function groupByCategory(commands: SlashCommand[]) {
  const groups: {
    category: SlashCommandCategory;
    label: string;
    items: SlashCommand[];
  }[] = [];
  const map = new Map<SlashCommandCategory, SlashCommand[]>();

  for (const cmd of commands) {
    let arr = map.get(cmd.category);
    if (!arr) {
      arr = [];
      map.set(cmd.category, arr);
    }
    arr.push(cmd);
  }

  for (const cat of CATEGORY_ORDER) {
    const items = map.get(cat);
    if (items && items.length > 0) {
      groups.push({ category: cat, label: CATEGORY_LABELS[cat], items });
    }
  }

  return groups;
}

interface SlashMenuProps {
  view: EditorView;
  slashState: SlashMenuState;
  onSelect: (cmd: SlashCommand) => void;
}

export function SlashMenu(props: SlashMenuProps) {
  let menuEl: HTMLDivElement | undefined;
  let selectedEl: HTMLDivElement | undefined;
  const [activeTab, setActiveTab] = createSignal<SlashCommandCategory | "all">("all");

  createEffect(() => {
    void props.slashState.active;
    setActiveTab("all");
  });

  const displayCommands = createMemo(() => {
    const tab = activeTab();
    if (tab === "all") return props.slashState.commands;
    return props.slashState.commands.filter((c) => c.category === tab);
  });

  const groups = createMemo(() => groupByCategory(displayCommands()));

  const availableTabs = createMemo(() => {
    const cats = new Set(props.slashState.commands.map((c) => c.category));
    return CATEGORY_ORDER.filter((c) => cats.has(c));
  });

  createEffect(() => {
    const menu = menuEl;
    if (!menu) return;

    const view = props.view;
    const pos = props.slashState.pos;

    const virtualEl = {
      getBoundingClientRect: () => {
        const coords = view.coordsAtPos(pos);
        return new DOMRect(coords.left, coords.bottom, 0, 0);
      },
    };

    computePosition(virtualEl, menu, {
      placement: "bottom-start",
      middleware: [offset(4), flip(), shift({ padding: 8 })],
    }).then(({ x, y }) => {
      menu.style.left = `${x}px`;
      menu.style.top = `${y}px`;
    });
  });

  createEffect(() => {
    void props.slashState.selectedIndex;
    selectedEl?.scrollIntoView({ block: "nearest" });
  });

  const selectedCommand = () => props.slashState.commands[props.slashState.selectedIndex];
  const isSearching = () => props.slashState.query.length > 0;

  return (
    <Show when={props.slashState.commands.length > 0}>
      <Portal>
        <div
          ref={(el) => {
            menuEl = el;
          }}
          class="fixed z-50 flex w-72 max-h-80 flex-col overflow-hidden border border-border/60 bg-muted/60 text-foreground shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]"
        >
          <Show when={!isSearching() && availableTabs().length > 1}>
            <Tabs
              value={activeTab()}
              onChange={(value: string) => setActiveTab(value as SlashCommandCategory | "all")}
              class="shrink-0 gap-0"
            >
              <TabsList class="h-auto w-full justify-start border-x-0 border-t-0 bg-transparent px-1 pt-1">
                <TabsTrigger value="all" class="h-8 flex-none px-2.5">
                  All
                </TabsTrigger>
                <For each={availableTabs()}>
                  {(cat) => (
                    <TabsTrigger value={cat} class="h-8 flex-none px-2.5">
                      {CATEGORY_LABELS[cat]}
                    </TabsTrigger>
                  )}
                </For>
              </TabsList>
            </Tabs>
          </Show>

          <Command shouldFilter={false} class="min-h-0 flex-1 bg-transparent">
            <CommandList class="max-h-none min-h-0 flex-1 p-1">
              <For each={groups()}>
                {(group) => (
                  <CommandGroup value={group.category}>
                    <Show when={activeTab() === "all" && !isSearching() && groups().length > 1}>
                      <div class="px-2 pb-1 pt-2 font-mono text-[10px] uppercase tracking-[0.3em] text-muted-foreground/60">
                        {group.label}
                      </div>
                    </Show>
                    <For each={group.items}>
                      {(cmd) => {
                        const isSelected = () => selectedCommand() === cmd;
                        const IconComp = ICON_MAP[cmd.icon];

                        return (
                          <CommandItem
                            ref={(el) => {
                              if (isSelected()) selectedEl = el;
                            }}
                            value={`${cmd.category}:${cmd.shortcut}:${cmd.label}`}
                            class={`flex w-full items-center gap-3 px-2 py-1.5 text-left transition-colors ${
                              isSelected() ? "bg-foreground text-background" : "hover:bg-muted"
                            }`}
                            onMouseDown={(e) => {
                              e.preventDefault();
                            }}
                            onSelect={() => props.onSelect(cmd)}
                          >
                            <span
                              class={`flex size-8 shrink-0 items-center justify-center border ${
                                isSelected()
                                  ? "border-background/30 bg-background/10"
                                  : "border-border/60 bg-background/50"
                              }`}
                            >
                              {IconComp && (
                                <IconComp
                                  size={16}
                                  class={isSelected() ? "text-background" : "text-muted-foreground"}
                                />
                              )}
                            </span>
                            <div class="flex min-w-0 flex-col">
                              <span class="text-sm font-medium leading-tight">{cmd.label}</span>
                              <span
                                class={`text-[11px] leading-tight ${
                                  isSelected() ? "text-background/60" : "text-muted-foreground"
                                }`}
                              >
                                {cmd.description}
                              </span>
                            </div>
                          </CommandItem>
                        );
                      }}
                    </For>
                  </CommandGroup>
                )}
              </For>
            </CommandList>
          </Command>
        </div>
      </Portal>
    </Show>
  );
}
