import { setBlockType } from "prosemirror-commands";
import type { Node as ProseMirrorNode, ResolvedPos, Schema } from "prosemirror-model";
import { wrapInList } from "prosemirror-schema-list";
import { Plugin, PluginKey, Selection } from "prosemirror-state";
import type { EditorView } from "prosemirror-view";

export type SlashCommandCategory = "text" | "list" | "other";

export const CATEGORY_LABELS: Record<SlashCommandCategory, string> = {
  text: "Text",
  list: "List",
  other: "Other",
};

export const CATEGORY_ORDER: SlashCommandCategory[] = ["text", "list", "other"];

export interface SlashCommand {
  label: string;
  description: string;
  shortcut: string;
  category: SlashCommandCategory;
  icon: string;
  execute: (view: EditorView) => boolean;
}

function buildCommands(schema: Schema): SlashCommand[] {
  const commands: SlashCommand[] = [];
  if (schema.nodes.paragraph) {
    commands.push({
      label: "Text",
      description: "Plain text block",
      shortcut: "p",
      category: "text",
      icon: "type",
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.paragraph);
        return cmd(view.state, view.dispatch);
      },
    });
  }
  if (schema.nodes.heading) {
    commands.push({
      label: "Heading 1",
      description: "Large section heading",
      shortcut: "h1",
      category: "text",
      icon: "heading-1",
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.heading, { level: 1 });
        return cmd(view.state, view.dispatch);
      },
    });
    commands.push({
      label: "Heading 2",
      description: "Medium section heading",
      shortcut: "h2",
      category: "text",
      icon: "heading-2",
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.heading, { level: 2 });
        return cmd(view.state, view.dispatch);
      },
    });
    commands.push({
      label: "Heading 3",
      description: "Small section heading",
      shortcut: "h3",
      category: "text",
      icon: "heading-3",
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.heading, { level: 3 });
        return cmd(view.state, view.dispatch);
      },
    });
  }
  if (schema.nodes.bullet_list) {
    commands.push({
      label: "Bullet List",
      description: "Unordered list with bullets",
      shortcut: "ul",
      category: "list",
      icon: "list",
      execute: (view) => {
        const cmd = wrapInList(schema.nodes.bullet_list);
        return cmd(view.state, view.dispatch);
      },
    });
    commands.push({
      label: "Task List",
      description: "Checklist item",
      shortcut: "todo",
      category: "list",
      icon: "check-square",
      execute: (view) => {
        const { $from } = view.state.selection;
        const from = $from.before();
        const to = $from.after();
        const paragraph = schema.nodes.paragraph.create();
        const item = schema.nodes.list_item.create({ checked: false }, [paragraph]);
        const list = schema.nodes.bullet_list.create(null, [item]);
        const tr = view.state.tr.replaceRangeWith(from, to, list);
        tr.setSelection(Selection.near(tr.doc.resolve(Math.min(from + 3, tr.doc.content.size))));
        view.dispatch(tr);
        return true;
      },
    });
  }
  if (schema.nodes.ordered_list) {
    commands.push({
      label: "Numbered List",
      description: "Ordered list with numbers",
      shortcut: "ol",
      category: "list",
      icon: "list-ordered",
      execute: (view) => {
        const cmd = wrapInList(schema.nodes.ordered_list);
        return cmd(view.state, view.dispatch);
      },
    });
  }
  if (schema.nodes.blockquote) {
    commands.push({
      label: "Quote",
      description: "Block quotation",
      shortcut: "quote",
      category: "text",
      icon: "quote",
      execute: (view) => {
        const { $from, $to } = view.state.selection;
        const range = $from.blockRange($to);
        if (!range) return false;
        const tr = view.state.tr.wrap(range, [{ type: schema.nodes.blockquote }]);
        view.dispatch(tr);
        return true;
      },
    });
  }
  if (schema.nodes.code_block) {
    commands.push({
      label: "Code",
      description: "Fenced code block",
      shortcut: "code",
      category: "other",
      icon: "code",
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.code_block);
        return cmd(view.state, view.dispatch);
      },
    });
  }
  if (schema.nodes.horizontal_rule) {
    commands.push({
      label: "Divider",
      description: "Horizontal separator",
      shortcut: "hr",
      category: "other",
      icon: "minus",
      execute: (view) => {
        const { $from } = view.state.selection;
        const tr = view.state.tr.replaceRangeWith(
          $from.before(),
          $from.after(),
          schema.nodes.horizontal_rule.create(),
        );
        view.dispatch(tr);
        return true;
      },
    });
  }
  if (schema.nodes.table && schema.nodes.table_row && schema.nodes.table_cell) {
    commands.push({
      label: "Table",
      description: "Table with header row",
      shortcut: "table",
      category: "other",
      icon: "table",
      execute: (view) => {
        const { $from } = view.state.selection;
        const from = $from.before();
        const to = $from.after();
        const rows = Array.from({ length: 3 }, (_, rowIndex) =>
          schema.nodes.table_row.create(
            null,
            Array.from({ length: 3 }, () => {
              const cellType =
                rowIndex === 0 && schema.nodes.table_header
                  ? schema.nodes.table_header
                  : schema.nodes.table_cell;
              return cellType.create(null, [schema.nodes.paragraph.create()]);
            }),
          ),
        );
        const table = schema.nodes.table.create(null, rows);
        const tr = view.state.tr.replaceRangeWith(from, to, table);
        tr.setSelection(Selection.near(tr.doc.resolve(Math.min(from + 3, tr.doc.content.size))));
        view.dispatch(tr);
        return true;
      },
    });
  }
  commands.sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category));
  return commands;
}

const slashCommandsKey = new PluginKey<SlashMenuState>("slashCommands");

export interface SlashMenuState {
  active: boolean;
  query: string;
  commands: SlashCommand[];
  selectedIndex: number;
  pos: number;
}

export const INACTIVE: SlashMenuState = {
  active: false,
  query: "",
  commands: [],
  selectedIndex: 0,
  pos: 0,
};

function selectedCommand(state: SlashMenuState): SlashCommand | null {
  if (state.commands.length === 0) return null;
  const index = Math.min(Math.max(state.selectedIndex, 0), state.commands.length - 1);
  return state.commands[index] ?? null;
}

function deleteSlashQuery(view: EditorView, state: SlashMenuState) {
  const from = state.pos;
  const to = view.state.selection.from;
  const tr =
    to > from
      ? view.state.tr.delete(from, to).setMeta(slashCommandsKey, INACTIVE)
      : view.state.tr.setMeta(slashCommandsKey, INACTIVE);
  view.dispatch(tr);
}

function textBeforeCursorOnCurrentLine(doc: ProseMirrorNode, $from: ResolvedPos): string {
  const textBeforeCursor = doc.textBetween($from.start(), $from.pos, "\n", "\n");
  return textBeforeCursor.slice(textBeforeCursor.lastIndexOf("\n") + 1);
}

function slashStartOnCurrentLine(doc: ProseMirrorNode, $from: ResolvedPos): number | null {
  if (!$from.parent.isTextblock || $from.pos <= $from.start()) return null;
  if (textBeforeCursorOnCurrentLine(doc, $from) !== "/") return null;
  return $from.pos - 1;
}

function isSlashCommandStartSelection(view: EditorView): boolean {
  if (!view.state.selection.empty) return false;
  const { $from } = view.state.selection;
  return $from.parent.isTextblock && textBeforeCursorOnCurrentLine(view.state.doc, $from) === "";
}

function sameCommands(a: SlashCommand[], b: SlashCommand[]): boolean {
  return a.length === b.length && a.every((command, index) => command === b[index]);
}

export function slashCommandsPlugin(schema: Schema): Plugin {
  const allCommands = buildCommands(schema);

  function filterCommands(query: string): SlashCommand[] {
    if (!query) return allCommands;
    const q = query.toLowerCase();
    return allCommands.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.shortcut.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        CATEGORY_LABELS[c.category].toLowerCase().includes(q),
    );
  }

  function openSlashMenu(view: EditorView, from: number, to: number): boolean {
    if (!isSlashCommandStartSelection(view)) return false;

    const tr = view.state.tr.insertText("/", from, to).setMeta(slashCommandsKey, {
      active: true,
      query: "",
      commands: allCommands,
      selectedIndex: 0,
      pos: from,
    } satisfies SlashMenuState);
    view.dispatch(tr);
    return true;
  }

  function executeSelectedCommand(view: EditorView, state: SlashMenuState): boolean {
    const cmd = selectedCommand(state);
    if (!cmd) return false;

    deleteSlashQuery(view, state);
    queueMicrotask(() => {
      cmd.execute(view);
      view.focus();
    });
    return true;
  }

  return new Plugin({
    key: slashCommandsKey,
    state: {
      init: () => INACTIVE,
      apply(tr, prev) {
        const meta = tr.getMeta(slashCommandsKey);
        if (meta !== undefined) return meta as SlashMenuState;
        if (!prev.active) return prev;

        const next = tr.docChanged
          ? {
              ...prev,
              pos: tr.mapping.map(prev.pos, -1),
            }
          : prev;

        if (tr.selectionSet && !tr.docChanged) {
          const cursor = tr.selection.from;
          const queryEnd = next.pos + next.query.length + 1;
          if (cursor < next.pos || cursor > queryEnd) return INACTIVE;
        }

        return next;
      },
    },
    appendTransaction(transactions, _oldState, newState) {
      if (!transactions.some((tr) => tr.docChanged)) return null;
      if (transactions.some((tr) => tr.getMeta(slashCommandsKey) !== undefined)) return null;
      if (!newState.selection.empty) return null;

      const state = slashCommandsKey.getState(newState) as SlashMenuState | undefined;
      const cursor = newState.selection.from;
      const { $from } = newState.selection;

      if (!state?.active) {
        const slashStart = slashStartOnCurrentLine(newState.doc, $from);
        if (slashStart === null) return null;

        return newState.tr.setMeta(slashCommandsKey, {
          active: true,
          query: "",
          commands: allCommands,
          selectedIndex: 0,
          pos: slashStart,
        } satisfies SlashMenuState);
      }

      if (state.pos < 0 || state.pos >= newState.doc.content.size || cursor < state.pos + 1) {
        return newState.tr.setMeta(slashCommandsKey, INACTIVE);
      }
      if (
        !$from.parent.isTextblock ||
        state.pos < $from.start() ||
        state.pos >= cursor ||
        cursor > $from.end()
      ) {
        return newState.tr.setMeta(slashCommandsKey, INACTIVE);
      }
      if (newState.doc.textBetween(state.pos, state.pos + 1, "", "") !== "/") {
        return newState.tr.setMeta(slashCommandsKey, INACTIVE);
      }

      const query = newState.doc.textBetween(state.pos + 1, cursor, "", "");
      const commands = filterCommands(query);
      const selectedIndex =
        commands.length === 0 ? 0 : Math.min(Math.max(state.selectedIndex, 0), commands.length - 1);
      if (
        query === state.query &&
        selectedIndex === state.selectedIndex &&
        sameCommands(commands, state.commands)
      ) {
        return null;
      }

      return newState.tr.setMeta(slashCommandsKey, {
        ...state,
        query,
        commands,
        selectedIndex,
      } satisfies SlashMenuState);
    },
    props: {
      handleKeyDown(view, event) {
        if (event.isComposing) return false;

        const state = slashCommandsKey.getState(view.state) as SlashMenuState | undefined;
        if (!state?.active) {
          if (event.key === "/") {
            const { from, to } = view.state.selection;
            if (openSlashMenu(view, from, to)) {
              event.preventDefault();
              return true;
            }
          }
          return false;
        }
        if (event.key === "Escape") {
          event.preventDefault();
          view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE));
          return true;
        }
        if (event.key === "ArrowDown") {
          event.preventDefault();
          if (state.commands.length === 0) return true;
          const next = {
            ...state,
            selectedIndex: (state.selectedIndex + 1) % state.commands.length,
          };
          view.dispatch(view.state.tr.setMeta(slashCommandsKey, next));
          return true;
        }
        if (event.key === "ArrowUp") {
          event.preventDefault();
          if (state.commands.length === 0) return true;
          const next = {
            ...state,
            selectedIndex:
              (state.selectedIndex - 1 + state.commands.length) % state.commands.length,
          };
          view.dispatch(view.state.tr.setMeta(slashCommandsKey, next));
          return true;
        }
        if (event.key === "Enter" || event.key === "Tab" || event.key === " ") {
          if (state.commands.length === 0) {
            view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE));
            return false;
          }

          event.preventDefault();
          executeSelectedCommand(view, state);
          return true;
        }
        if (event.key === "Backspace") {
          if (state.query.length === 0) {
            view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE));
            return false;
          }
          event.preventDefault();
          const newQuery = state.query.slice(0, -1);
          const filtered = filterCommands(newQuery);
          const cursorPos = view.state.selection.from;
          const tr = view.state.tr.delete(cursorPos - 1, cursorPos).setMeta(slashCommandsKey, {
            ...state,
            query: newQuery,
            commands: filtered,
            selectedIndex: 0,
          } satisfies SlashMenuState);
          view.dispatch(tr);
          return true;
        }
        if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
          event.preventDefault();
          const newQuery = state.query + event.key;
          const filtered = filterCommands(newQuery);
          const cursorPos = view.state.selection.from;
          const tr = view.state.tr
            .insertText(event.key, cursorPos, cursorPos)
            .setMeta(slashCommandsKey, {
              ...state,
              query: newQuery,
              commands: filtered,
              selectedIndex: 0,
            } satisfies SlashMenuState);
          view.dispatch(tr);
          return true;
        }
        return false;
      },
      handleTextInput(view, from, to, text) {
        if (text !== "/") return false;
        const state = slashCommandsKey.getState(view.state) as SlashMenuState | undefined;
        if (state?.active) return false;
        return openSlashMenu(view, from, to);
      },
    },
  });
}
