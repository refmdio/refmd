import { toggleMark, baseKeymap } from "prosemirror-commands";
import { dropCursor } from "prosemirror-dropcursor";
import { gapCursor } from "prosemirror-gapcursor";
import { keymap } from "prosemirror-keymap";
import type { Schema } from "prosemirror-model";
import type { Plugin } from "prosemirror-state";
import { columnResizing, goToNextCell, tableEditing } from "prosemirror-tables";
import { markdownInputRules } from "./plugin-input-rules";
import { taskListPlugin } from "./plugin-task-list";

export function buildCollabPlugins(schema: Schema): Plugin[] {
  const plugins: Plugin[] = [];

  const markKeys: Record<string, ReturnType<typeof toggleMark>> = {};

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
  if (schema.nodes.table) {
    markKeys.Tab = goToNextCell(1);
    markKeys["Shift-Tab"] = goToNextCell(-1);
  }

  plugins.push(markdownInputRules(schema));
  plugins.push(keymap(markKeys));
  plugins.push(keymap(baseKeymap));
  plugins.push(dropCursor());
  plugins.push(gapCursor());
  if (schema.nodes.list_item) {
    plugins.push(taskListPlugin());
  }
  if (schema.nodes.table) {
    plugins.push(columnResizing(), tableEditing());
  }

  return plugins;
}
