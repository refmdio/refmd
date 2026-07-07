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
import { Command, CommandEmpty, CommandGroup, CommandItem, CommandList } from "@/shared/ui/command";

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

function commandValue(command: SlashCommand): string {
  return `${command.category}:${command.shortcut}:${command.label}`;
}

function elementFromNode(node: Node | null): HTMLElement | null {
  if (node instanceof HTMLElement) return node;
  if (node instanceof Text) return node.parentElement;
  return null;
}

function topLevelEditorChild(view: EditorView, element: HTMLElement | null): HTMLElement | null {
  if (!element) return null;

  let current: HTMLElement | null = element;
  while (current?.parentElement && current.parentElement !== view.dom) {
    current = current.parentElement;
  }

  return current?.parentElement === view.dom ? current : element;
}

function blockElementAtPos(view: EditorView, blockPos: number): HTMLElement | null {
  const nodeDom = view.nodeDOM(blockPos);
  const direct = topLevelEditorChild(view, elementFromNode(nodeDom));
  if (direct) return direct;

  return blockElementNearPos(view, blockPos + 1);
}

function blockElementNearPos(view: EditorView, pos: number): HTMLElement | null {
  try {
    const safePos = Math.max(0, Math.min(pos, view.state.doc.content.size));
    return topLevelEditorChild(view, elementFromNode(view.domAtPos(safePos).node));
  } catch {
    return null;
  }
}

function anchorRectFromElement(element: HTMLElement): DOMRect {
  const rect = element.getBoundingClientRect();
  return new DOMRect(rect.left, rect.bottom, 0, 0);
}

function isUsableAnchorRect(rect: DOMRect): boolean {
  return Number.isFinite(rect.left) && Number.isFinite(rect.bottom);
}

interface SlashMenuProps {
  view: EditorView;
  slashState: SlashMenuState;
  onDismiss: () => void;
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
    const state = props.slashState;
    const pos = state.anchorPos ?? state.pos;
    let dismissedForStaleAnchor = false;

    const readAnchorRect = () => {
      if (state.mode === "virtual" && typeof state.insertAfterBlockPos === "number") {
        const blockElement = blockElementAtPos(view, state.insertAfterBlockPos);
        if (blockElement) {
          const rect = anchorRectFromElement(blockElement);
          if (isUsableAnchorRect(rect)) return rect;
        }
      }

      try {
        const safePos = Math.max(0, Math.min(pos, view.state.doc.content.size));
        const coords = view.coordsAtPos(safePos);
        return new DOMRect(coords.left, coords.bottom, 0, 0);
      } catch {
        const blockElement = blockElementNearPos(view, pos);
        if (blockElement) {
          const rect = anchorRectFromElement(blockElement);
          if (isUsableAnchorRect(rect)) return rect;
        }
        return null;
      }
    };

    const dismissForStaleAnchor = () => {
      if (dismissedForStaleAnchor) return;
      dismissedForStaleAnchor = true;
      menu.style.visibility = "hidden";
      queueMicrotask(props.onDismiss);
    };

    const constrainPosition = (x: number, y: number) => {
      const menuWidth = menu.offsetWidth || 320;
      const menuHeight = menu.offsetHeight || 320;
      const maxX = Math.max(8, window.innerWidth - menuWidth - 8);
      const maxY = Math.max(8, window.innerHeight - menuHeight - 8);
      return {
        left: Math.min(Math.max(x, 8), maxX),
        top: Math.min(Math.max(y, 8), maxY),
      };
    };

    const applyConstrainedPosition = (x: number, y: number) => {
      const { left, top } = constrainPosition(x, y);
      menu.style.visibility = "";
      menu.style.left = `${left}px`;
      menu.style.top = `${top}px`;
    };

    const applyFallbackPosition = () => {
      const rect = readAnchorRect();
      if (!rect) {
        dismissForStaleAnchor();
        return null;
      }
      applyConstrainedPosition(rect.left, rect.bottom + 4);
      return rect;
    };

    const virtualEl = {
      getBoundingClientRect: () => readAnchorRect() ?? new DOMRect(0, 0, 0, 0),
      contextElement: view.dom,
    };

    const updatePosition = () => {
      const fallbackRect = applyFallbackPosition();
      if (!fallbackRect) return;
      void computePosition(virtualEl, menu, {
        placement: "bottom-start",
        middleware: [offset(4), flip(), shift({ padding: 8 })],
      })
        .then(({ x, y }) => {
          const anchorRect = readAnchorRect() ?? fallbackRect;
          const fallback = constrainPosition(anchorRect.left, anchorRect.bottom + 4);
          const collapsedToOrigin = (fallback.left > 16 && x <= 8) || (fallback.top > 16 && y <= 8);
          if (!Number.isFinite(x) || !Number.isFinite(y) || collapsedToOrigin) {
            applyFallbackPosition();
            return;
          }
          applyConstrainedPosition(x, y);
        })
        .catch(applyFallbackPosition);
    };

    const cleanup = autoUpdate(virtualEl, menu, updatePosition, {
      ancestorResize: true,
      ancestorScroll: true,
      elementResize: true,
    });
    onCleanup(cleanup);
    updatePosition();
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
  const selectedCommandValue = () => {
    const command = selectedCommand();
    return command ? commandValue(command) : "";
  };
  const isSearching = () => props.slashState.query.length > 0;
  const dismiss = (event?: Event, options: { focusEditor?: boolean } = {}) => {
    event?.preventDefault();
    props.onDismiss();
    if (options.focusEditor) queueMicrotask(() => props.view.focus());
  };
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

  createEffect(() => {
    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (menuEl?.contains(target) || props.view.dom.contains(target)) return;
      dismiss();
    };

    document.addEventListener("pointerdown", handlePointerDown, true);
    onCleanup(() => document.removeEventListener("pointerdown", handlePointerDown, true));
  });

  return (
    <Show when={props.slashState.active}>
      <Portal>
        <Command
          ref={(el) => {
            menuEl = el;
          }}
          id={menuId}
          label="Block commands"
          shouldFilter={false}
          value={selectedCommandValue()}
          class="refmd-slash-menu fixed z-50 h-auto max-h-80 w-80"
          data-refmd-editor-chrome="slash-menu"
          onFocusOut={(event) => {
            const nextTarget = event.relatedTarget;
            if (nextTarget instanceof Node && menuEl?.contains(nextTarget)) return;
            queueMicrotask(() => {
              const activeElement = document.activeElement;
              if (activeElement && menuEl?.contains(activeElement)) return;
              if (activeElement && props.view.dom.contains(activeElement)) return;
              props.onDismiss();
            });
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") dismiss(event, { focusEditor: true });
          }}
        >
          <div id={statusId} class="sr-only" role="status" aria-live="polite">
            {resultStatus()}
          </div>
          <CommandList
            aria-activedescendant={activeOptionId()}
            aria-describedby={statusId}
            label="Block commands"
          >
            <Show
              when={groups().length > 0}
              fallback={<CommandEmpty>No matching blocks</CommandEmpty>}
            >
              <For each={groups()}>
                {(group) => (
                  <CommandGroup
                    heading={!isSearching() && groups().length > 1 ? group.label : undefined}
                    value={group.category}
                  >
                    <For each={group.items}>
                      {(cmd) => {
                        const IconComp = ICON_MAP[cmd.icon];
                        let selecting = false;
                        const selectCommand = () => {
                          if (selecting) return;
                          selecting = true;
                          props.onSelect(cmd);
                          setTimeout(() => {
                            selecting = false;
                          }, 0);
                        };

                        return (
                          <CommandItem
                            value={commandValue(cmd)}
                            tabIndex={-1}
                            data-refmd-slash-option-id={optionId(cmd)}
                            onMouseDown={(event) => event.preventDefault()}
                            onSelect={selectCommand}
                            onKeyDown={(event) => {
                              if (event.key !== "Enter" && event.key !== " ") return;
                              event.preventDefault();
                              selectCommand();
                            }}
                          >
                            <span class="flex size-7 shrink-0 items-center justify-center">
                              {IconComp && <IconComp size={16} class="text-current opacity-70" />}
                            </span>
                            <div class="flex min-w-0 flex-col normal-case tracking-normal">
                              <span class="text-sm leading-tight">{cmd.label}</span>
                              <span class="text-[11px] leading-tight opacity-70">
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
            </Show>
          </CommandList>
        </Command>
      </Portal>
    </Show>
  );
}
