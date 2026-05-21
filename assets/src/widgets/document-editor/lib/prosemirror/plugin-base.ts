import { toggleMark, baseKeymap } from "prosemirror-commands";
import { dropCursor } from "prosemirror-dropcursor";
import { gapCursor } from "prosemirror-gapcursor";
import { keymap } from "prosemirror-keymap";
import type { Schema } from "prosemirror-model";
import type { Plugin } from "prosemirror-state";
import { markdownInputRules } from "./plugin-input-rules";

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

  plugins.push(markdownInputRules(schema));
  plugins.push(keymap(markKeys));
  plugins.push(keymap(baseKeymap));
  plugins.push(dropCursor());
  plugins.push(gapCursor());

  return plugins;
}
