import { createEffect, createMemo, createSignal, For, onCleanup, Show } from "solid-js";
import { Portal } from "solid-js/web";
import type { EditorView } from "prosemirror-view";
import { autoUpdate, computePosition, offset, flip, shift } from "@floating-ui/dom";
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
  SquareCheck,
  Table,
} from "lucide-solid";
import type { LucideProps } from "lucide-solid";
import type { Component } from "solid-js";
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
  "check-square": SquareCheck,
  table: Table,
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
  const menuId = `refmd-slash-menu-${Math.random().toString(36).slice(2)}`;
  const statusId = `${menuId}-status`;
  let menuEl: HTMLDivElement | undefined;
  const [activeOptionId, setActiveOptionId] = createSignal<string | undefined>();

  const groups = createMemo(() => groupByCategory(props.slashState.commands));
  const optionId = (cmd: SlashCommand) => {
    const index = props.slashState.commands.indexOf(cmd);
    return `${menuId}-option-${Math.max(0, index)}`;
  };

  createEffect(() => {
    const menu = menuEl;
    if (!menu) return;

    const view = props.view;
    const pos = props.slashState.pos;

    const virtualEl = {
      getBoundingClientRect: () => {
        const safePos = Math.max(0, Math.min(pos, view.state.doc.content.size));
        const coords = view.coordsAtPos(safePos);
        return new DOMRect(coords.left, coords.bottom, 0, 0);
      },
      contextElement: view.dom,
    };

    const updatePosition = () =>
      computePosition(virtualEl, menu, {
        placement: "bottom-start",
        middleware: [offset(4), flip(), shift({ padding: 8 })],
      }).then(({ x, y }) => {
        menu.style.left = `${x}px`;
        menu.style.top = `${y}px`;
      });

    const cleanup = autoUpdate(virtualEl, menu, updatePosition, {
      ancestorResize: true,
      ancestorScroll: true,
      elementResize: true,
    });
    onCleanup(cleanup);
    void updatePosition();
  });

  createEffect(() => {
    void props.slashState.query;
    void props.slashState.selectedIndex;
    queueMicrotask(() => {
      const selected = menuEl?.querySelector<HTMLElement>('[role="option"][aria-selected="true"]');
      setActiveOptionId(selected?.id || undefined);
      selected?.scrollIntoView({ block: "nearest" });
    });
  });

  const selectedCommand = () => props.slashState.commands[props.slashState.selectedIndex];
  const isSearching = () => props.slashState.query.length > 0;
  const resultStatus = () => {
    const count = props.slashState.commands.length;
    const query = props.slashState.query.trim();
    if (count === 0) {
      return query ? `No block commands match ${query}.` : "No block commands are available.";
    }
    const selected = selectedCommand();
    const countText = `${count} block command${count === 1 ? "" : "s"} available`;
    const queryText = query ? ` for ${query}` : "";
    const selectedText = selected ? `. ${selected.label} selected.` : ".";
    return `${countText}${queryText}${selectedText}`;
  };

  return (
    <Show when={props.slashState.active}>
      <Portal>
        <div
          ref={(el) => {
            menuEl = el;
          }}
          id={menuId}
          aria-label="Block commands"
          aria-activedescendant={activeOptionId()}
          aria-describedby={statusId}
          class="fixed z-50 flex w-72 max-h-80 flex-col overflow-hidden border border-border/60 bg-muted/60 text-foreground shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]"
          role="listbox"
        >
          <div id={statusId} class="sr-only" role="status" aria-live="polite">
            {resultStatus()}
          </div>
          <div class="min-h-0 flex-1 overflow-y-auto p-1">
            <Show
              when={groups().length > 0}
              fallback={
                <div class="px-3 py-4 text-sm text-muted-foreground">No matching blocks</div>
              }
            >
              <For each={groups()}>
                {(group) => (
                  <div role="group" aria-label={group.label}>
                    <Show when={!isSearching() && groups().length > 1}>
                      <div class="px-2 pb-1 pt-2 font-mono text-[10px] uppercase tracking-[0.3em] text-muted-foreground/60">
                        {group.label}
                      </div>
                    </Show>
                    <For each={group.items}>
                      {(cmd) => {
                        const isSelected = () => selectedCommand() === cmd;
                        const IconComp = ICON_MAP[cmd.icon];

                        return (
                          <div
                            id={optionId(cmd)}
                            data-refmd-slash-option-id={optionId(cmd)}
                            data-selected={isSelected() ? "true" : undefined}
                            aria-selected={isSelected() ? "true" : "false"}
                            role="option"
                            class={`flex w-full cursor-default items-center gap-3 px-2 py-1.5 text-left transition-colors ${
                              isSelected() ? "bg-foreground text-background" : "hover:bg-muted"
                            }`}
                            onMouseDown={(e) => {
                              e.preventDefault();
                              props.onSelect(cmd);
                            }}
                            onClick={() => props.onSelect(cmd)}
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
                          </div>
                        );
                      }}
                    </For>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </div>
      </Portal>
    </Show>
  );
}
