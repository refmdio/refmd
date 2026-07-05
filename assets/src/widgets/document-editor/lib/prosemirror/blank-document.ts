import type { Node as ProseMirrorNode } from "prosemirror-model";

export function isBlankProseMirrorDocument(doc: ProseMirrorNode): boolean {
  if (doc.childCount === 0) return true;
  if (doc.childCount !== 1) return false;

  const onlyChild = doc.firstChild;
  return Boolean(
    onlyChild?.isTextblock && !onlyChild.type.spec.code && onlyChild.content.size === 0,
  );
}
