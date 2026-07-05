import type { NodeType, ResolvedPos, Schema } from "prosemirror-model";
import type { EditorState } from "prosemirror-state";
import type { EditorView } from "prosemirror-view";
import { setBlockType, toggleMark, wrapIn } from "prosemirror-commands";
import { wrapInList } from "prosemirror-schema-list";

export type FloatingToolbarActionId =
  | "strong"
  | "em"
  | "strikethrough"
  | "code"
  | "link"
  | "paragraph"
  | "heading1"
  | "heading2"
  | "blockquote"
  | "bullet_list"
  | "ordered_list"
  | "task_list";

export function isMarkActive(state: EditorState, markName: string): boolean {
  const markType = state.schema.marks[markName];
  if (!markType) return false;
  const { from, $from, to, empty } = state.selection;
  if (empty) {
    return !!markType.isInSet(state.storedMarks || $from.marks());
  }
  return state.doc.rangeHasMark(from, to, markType);
}

function hasAncestor(state: EditorState, nodeName: string): boolean {
  const { $from } = state.selection;
  for (let depth = $from.depth; depth > 0; depth -= 1) {
    if ($from.node(depth).type === state.schema.nodes[nodeName]) return true;
  }
  return false;
}

export function isFloatingToolbarActionActive(
  state: EditorState,
  actionId: FloatingToolbarActionId,
): boolean {
  if (state.schema.marks[actionId]) return isMarkActive(state, actionId);
  if (actionId === "link") return isMarkActive(state, "link");

  const { $from } = state.selection;
  switch (actionId) {
    case "paragraph":
      return $from.parent.type === state.schema.nodes.paragraph;
    case "heading1":
      return $from.parent.type === state.schema.nodes.heading && $from.parent.attrs.level === 1;
    case "heading2":
      return $from.parent.type === state.schema.nodes.heading && $from.parent.attrs.level === 2;
    case "blockquote":
      return hasAncestor(state, "blockquote");
    case "bullet_list":
      return (
        hasAncestor(state, "bullet_list") && !isFloatingToolbarActionActive(state, "task_list")
      );
    case "ordered_list":
      return hasAncestor(state, "ordered_list");
    case "task_list":
      return selectedListItemPositions(state).some(
        (pos) => typeof state.doc.nodeAt(pos)?.attrs.checked === "boolean",
      );
    default:
      return false;
  }
}

function selectedListItemPositions(state: EditorState): number[] {
  const positions = new Set<number>();
  const addAncestors = (pos: ResolvedPos) => {
    for (let depth = pos.depth; depth > 0; depth -= 1) {
      if (pos.node(depth).type === state.schema.nodes.list_item) {
        positions.add(pos.before(depth));
      }
    }
  };
  addAncestors(state.selection.$from);
  addAncestors(state.selection.$to);
  state.doc.nodesBetween(state.selection.from, state.selection.to, (node, pos) => {
    if (node.type === state.schema.nodes.list_item) positions.add(pos);
  });
  return [...positions].sort((a, b) => b - a);
}

function setSelectedListItemsChecked(view: EditorView, checked: boolean | null): boolean {
  const positions = selectedListItemPositions(view.state);
  if (positions.length === 0) return false;

  let tr = view.state.tr;
  for (const pos of positions) {
    const node = tr.doc.nodeAt(pos);
    if (!node || node.type !== view.state.schema.nodes.list_item) continue;
    tr = tr.setNodeMarkup(pos, undefined, { ...node.attrs, checked });
  }
  view.dispatch(tr.scrollIntoView());
  return true;
}

function wrapSelectionInList(view: EditorView, listType: NodeType): boolean {
  return wrapInList(listType)(view.state, view.dispatch);
}

function runTaskListAction(view: EditorView): boolean {
  if (selectedListItemPositions(view.state).length > 0) {
    return setSelectedListItemsChecked(view, false);
  }
  const listType = view.state.schema.nodes.bullet_list;
  if (!listType || !wrapSelectionInList(view, listType)) return false;
  return setSelectedListItemsChecked(view, false);
}

export function runFloatingToolbarAction(
  view: EditorView,
  actionId: FloatingToolbarActionId,
  options: { href?: string | null } = {},
): boolean {
  const schema: Schema = view.state.schema;

  if (actionId === "link") {
    const markType = schema.marks.link;
    if (!markType || view.state.selection.empty) return false;
    const active = isMarkActive(view.state, "link");
    const attrs = active ? undefined : { href: options.href, title: null };
    if (!active && !options.href) return false;
    return toggleMark(markType, attrs)(view.state, view.dispatch);
  }

  if (schema.marks[actionId]) {
    return toggleMark(schema.marks[actionId])(view.state, view.dispatch);
  }

  switch (actionId) {
    case "paragraph":
      return setBlockType(schema.nodes.paragraph)(view.state, view.dispatch);
    case "heading1":
      return setBlockType(schema.nodes.heading, { level: 1 })(view.state, view.dispatch);
    case "heading2":
      return setBlockType(schema.nodes.heading, { level: 2 })(view.state, view.dispatch);
    case "blockquote":
      return wrapIn(schema.nodes.blockquote)(view.state, view.dispatch);
    case "bullet_list":
      if (setSelectedListItemsChecked(view, null)) return true;
      return wrapSelectionInList(view, schema.nodes.bullet_list);
    case "ordered_list":
      if (setSelectedListItemsChecked(view, null)) return true;
      return wrapSelectionInList(view, schema.nodes.ordered_list);
    case "task_list":
      return runTaskListAction(view);
    default:
      return false;
  }
}
