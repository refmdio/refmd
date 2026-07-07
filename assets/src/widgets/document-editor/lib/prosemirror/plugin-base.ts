import { toggleMark, baseKeymap, chainCommands } from "prosemirror-commands";
import { dropCursor } from "prosemirror-dropcursor";
import { gapCursor } from "prosemirror-gapcursor";
import { keymap } from "prosemirror-keymap";
import type { Schema } from "prosemirror-model";
import type { Command, Plugin } from "prosemirror-state";
import { liftListItem, sinkListItem } from "prosemirror-schema-list";
import { columnResizing, goToNextCell, tableEditing } from "prosemirror-tables";
import { markdownInputRules } from "./plugin-input-rules";
import { markdownPasteDropPlugin } from "./plugin-markdown-paste-drop";
import { taskListPlugin } from "./plugin-task-list";

export function buildCollabPlugins(schema: Schema): Plugin[] {
  const plugins: Plugin[] = [];

  const markKeys: Record<string, Command> = {};

  if (schema.marks.strong) {
    markKeys["Mod-b"] = toggleMark(schema.marks.strong);
  }
  if (schema.marks.em) {
    markKeys["Mod-i"] = toggleMark(schema.marks.em);
  }
  if (schema.marks.code) {
    markKeys["Mod-`"] = toggleMark(schema.marks.code);
  }
  if (schema.marks.strikethrough) {
    markKeys["Mod-Shift-s"] = toggleMark(schema.marks.strikethrough);
  }
  const listItemType = schema.nodes.list_item;
  if (schema.nodes.table && listItemType) {
    markKeys.Tab = chainCommands(goToNextCell(1), sinkListItem(listItemType));
    markKeys["Shift-Tab"] = chainCommands(goToNextCell(-1), liftListItem(listItemType));
  } else if (schema.nodes.table) {
    markKeys.Tab = goToNextCell(1);
    markKeys["Shift-Tab"] = goToNextCell(-1);
  } else if (listItemType) {
    markKeys.Tab = sinkListItem(listItemType);
    markKeys["Shift-Tab"] = liftListItem(listItemType);
  }

  plugins.push(markdownInputRules(schema));
  plugins.push(markdownPasteDropPlugin(schema));
  plugins.push(keymap(markKeys));
  plugins.push(keymap(baseKeymap));
  plugins.push(
    dropCursor({ color: "var(--primary)", width: 3, class: "refmd-wysiwyg-dropcursor" }),
  );
  plugins.push(gapCursor());
  if (schema.nodes.list_item) {
    plugins.push(taskListPlugin());
  }
  if (schema.nodes.table) {
    plugins.push(columnResizing(), tableEditing());
  }

  return plugins;
}
