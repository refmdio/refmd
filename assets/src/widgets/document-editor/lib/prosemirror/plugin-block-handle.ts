import type { Node as ProseMirrorNode, Slice } from "prosemirror-model";
import { NodeSelection, Plugin, TextSelection, type PluginView } from "prosemirror-state";
import { dropPoint } from "prosemirror-transform";
import type { EditorView } from "prosemirror-view";

const HANDLE_BUTTON_SIZE = 20;
const HANDLE_BRIDGE_WIDTH = 10;
const HIDE_HANDLE_DELAY_MS = 140;
const POINTER_DRAG_THRESHOLD_PX = 4;
const TRANSIENT_EMPTY_SYNC_GRACE_MS = 250;
const DRAGGABLE_TOP_LEVEL_BLOCK_TYPES = new Set([
  "paragraph",
  "heading",
  "code_block",
  "blockquote",
]);

export interface BlockHandleViewState {
  dragging: boolean;
  height: number;
  left: number;
  top: number;
  visible: boolean;
}

export interface BlockHandleViewController {
  attachHandleElement(element: HTMLDivElement | null): void;
  beginMouseDrag(event: MouseEvent): void;
  beginNativeDrag(event: DragEvent): void;
  beginPointerDrag(event: PointerEvent): void;
  finishDrag(): void;
  getState(): BlockHandleViewState;
  openBlockMenu(event?: Event): void;
  refreshVisibleHandle(): void;
  setMenuFrozen(frozen: boolean): void;
  subscribe(listener: (state: BlockHandleViewState) => void): () => void;
}

export type BlockHandlePluginViewFactory = (
  view: EditorView,
  controller: BlockHandleViewController,
) => PluginView;

interface BlockHandlePluginOptions {
  createHandleView: BlockHandlePluginViewFactory;
  openBlockMenuBelow?: (view: EditorView, blockPos: number) => boolean;
}

interface PointerDragState {
  lastDropPos: number | null;
  pointerId: number | null;
  slice: Slice;
  startDoc: ProseMirrorNode;
  sourceNode: ProseMirrorNode;
  sourcePos: number;
  startX: number;
  startY: number;
  started: boolean;
}

function isDraggableTopLevelBlock(
  node: ProseMirrorNode | null | undefined,
): node is ProseMirrorNode {
  return !!node && node.isBlock && DRAGGABLE_TOP_LEVEL_BLOCK_TYPES.has(node.type.name);
}

export function blockHandlePlugin(options: BlockHandlePluginOptions): Plugin {
  let handleEl: HTMLDivElement | null = null;
  let handleView: PluginView | null = null;
  let dragPreviewEl: HTMLDivElement | null = null;
  let dropCursorEl: HTMLDivElement | null = null;
  let pointerDragState: PointerDragState | null = null;
  let transientEmptyDragTimer: ReturnType<typeof setTimeout> | null = null;
  let previousBodyCursor: string | null = null;
  let activeBlockPos = -1;
  let activeBlockNode: ProseMirrorNode | null = null;
  let menuFrozen = false;
  let activeView: EditorView | null = null;
  let hideTimer: ReturnType<typeof setTimeout> | null = null;
  let viewState: BlockHandleViewState = {
    dragging: false,
    height: HANDLE_BUTTON_SIZE,
    left: 0,
    top: 0,
    visible: false,
  };
  const subscribers = new Set<(state: BlockHandleViewState) => void>();

  function emitViewState() {
    for (const subscriber of subscribers) subscriber(viewState);
  }

  function setViewState(nextState: Partial<BlockHandleViewState>) {
    viewState = {
      ...viewState,
      ...nextState,
    };
    emitViewState();
  }

  function clearHideTimer() {
    if (hideTimer === null) return;
    clearTimeout(hideTimer);
    hideTimer = null;
  }

  function clearTransientEmptyDragTimer() {
    if (transientEmptyDragTimer === null) return;
    clearTimeout(transientEmptyDragTimer);
    transientEmptyDragTimer = null;
  }

  function handleContainsFocus() {
    return (
      !!handleEl &&
      document.activeElement instanceof Node &&
      handleEl.contains(document.activeElement)
    );
  }

  function targetIsHandle(target: EventTarget | null): boolean {
    return target instanceof Node && !!handleEl?.contains(target);
  }

  function hideHandle() {
    clearHideTimer();
    if (handleContainsFocus()) return;
    setViewState({ visible: false });
  }

  function setDragHandleActive(active: boolean) {
    if (active) clearHideTimer();
    setViewState({ dragging: active, visible: active ? true : viewState.visible });
  }

  function cleanupDragPreview() {
    dragPreviewEl?.remove();
    dragPreviewEl = null;
  }

  function cleanupDropCursor() {
    dropCursorEl?.remove();
    dropCursorEl = null;
  }

  function createDragPreview(nodeText: string, sourceDom: HTMLElement | null): HTMLDivElement {
    cleanupDragPreview();
    const preview = document.createElement("div");
    preview.className = "pm-block-drag-preview";
    preview.textContent = nodeText.trim() || "Empty block";

    const sourceRect = sourceDom?.getBoundingClientRect();
    if (sourceRect && sourceRect.width > 0) {
      preview.style.width = `${Math.max(180, Math.min(sourceRect.width, 520))}px`;
    }

    document.body.appendChild(preview);
    dragPreviewEl = preview;
    return preview;
  }

  function positionDragPreview(event: MouseEvent) {
    if (!dragPreviewEl) return;
    dragPreviewEl.classList.add("visible");
    dragPreviewEl.style.left = `${event.clientX + 12}px`;
    dragPreviewEl.style.top = `${event.clientY + 12}px`;
    dragPreviewEl.style.zIndex = "1000";
  }

  function ensureDropCursor(view: EditorView): HTMLDivElement {
    if (dropCursorEl) return dropCursorEl;

    const parent =
      view.dom.offsetParent instanceof HTMLElement ? view.dom.offsetParent : document.body;
    const cursor = document.createElement("div");
    cursor.className = "refmd-wysiwyg-dropcursor refmd-wysiwyg-pointer-dropcursor";
    cursor.style.position = "absolute";
    cursor.style.zIndex = "50";
    cursor.style.pointerEvents = "none";
    parent.appendChild(cursor);
    dropCursorEl = cursor;
    return cursor;
  }

  function updateDropCursor(view: EditorView, dropPos: number): boolean {
    const safeDropPos = Math.max(0, Math.min(dropPos, view.state.doc.content.size));
    const $pos = view.state.doc.resolve(safeDropPos);
    const isBlock = !$pos.parent.inlineContent;
    const editorDom = view.dom;
    const editorRect = editorDom.getBoundingClientRect();
    const scaleX = editorRect.width / editorDom.offsetWidth || 1;
    const scaleY = editorRect.height / editorDom.offsetHeight || 1;

    let rect: { bottom: number; left: number; right: number; top: number } | null = null;
    if (isBlock) {
      const before = $pos.nodeBefore;
      const after = $pos.nodeAfter;
      if (before || after) {
        const nodeDom = view.nodeDOM(safeDropPos - (before ? before.nodeSize : 0));
        if (nodeDom instanceof HTMLElement) {
          const nodeRect = nodeDom.getBoundingClientRect();
          let top = before ? nodeRect.bottom : nodeRect.top;
          const afterDom = before && after ? view.nodeDOM(safeDropPos) : null;
          if (afterDom instanceof HTMLElement) {
            top = (top + afterDom.getBoundingClientRect().top) / 2;
          }
          const halfWidth = 1.5 * scaleY;
          rect = {
            bottom: top + halfWidth,
            left: nodeRect.left,
            right: nodeRect.right,
            top: top - halfWidth,
          };
        }
      }
    }

    if (!rect) {
      const coords = view.coordsAtPos(safeDropPos);
      const halfWidth = 1.5 * scaleX;
      rect = {
        bottom: coords.bottom,
        left: coords.left - halfWidth,
        right: coords.left + halfWidth,
        top: coords.top,
      };
    }

    const parent =
      view.dom.offsetParent instanceof HTMLElement ? view.dom.offsetParent : document.body;
    const parentRect = parent.getBoundingClientRect();
    const parentScaleX = parentRect.width / parent.offsetWidth || 1;
    const parentScaleY = parentRect.height / parent.offsetHeight || 1;
    const parentLeft = parentRect.left - parent.scrollLeft * parentScaleX;
    const parentTop = parentRect.top - parent.scrollTop * parentScaleY;

    const cursor = ensureDropCursor(view);
    cursor.classList.toggle("prosemirror-dropcursor-block", isBlock);
    cursor.classList.toggle("prosemirror-dropcursor-inline", !isBlock);
    cursor.style.left = `${(rect.left - parentLeft) / scaleX}px`;
    cursor.style.top = `${(rect.top - parentTop) / scaleY}px`;
    cursor.style.width = `${(rect.right - rect.left) / scaleX}px`;
    cursor.style.height = `${(rect.bottom - rect.top) / scaleY}px`;
    return true;
  }

  function blockDropPosFromPointer(
    view: EditorView,
    event: MouseEvent,
    slice: Slice,
  ): number | null {
    let targetPos: number | null = null;
    let afterLastBlockPos: number | null = null;

    view.state.doc.forEach((node, offset) => {
      if (!node.isBlock || targetPos !== null) return;
      const dom = view.nodeDOM(offset);
      if (!(dom instanceof HTMLElement)) return;

      const rect = dom.getBoundingClientRect();
      afterLastBlockPos = offset + node.nodeSize;
      if (event.clientY < rect.top + rect.height / 2) {
        targetPos = offset;
      }
    });

    targetPos ??= afterLastBlockPos;
    if (targetPos === null) {
      const pos = view.posAtCoords({ left: event.clientX, top: event.clientY });
      targetPos = pos?.pos ?? null;
      if (targetPos !== null) return dropPoint(view.state.doc, targetPos, slice);
    }
    return targetPos;
  }

  function refreshPointerDragStateForCurrentDoc(view: EditorView): boolean {
    const dragState = pointerDragState;
    if (!dragState) return true;
    if (view.state.doc.eq(dragState.startDoc)) {
      clearTransientEmptyDragTimer();
      return true;
    }

    const currentNode = view.state.doc.nodeAt(dragState.sourcePos);
    if (currentNode?.eq(dragState.sourceNode)) {
      clearTransientEmptyDragTimer();
      dragState.startDoc = view.state.doc;
      dragState.slice = view.state.doc.slice(
        dragState.sourcePos,
        dragState.sourcePos + currentNode.nodeSize,
      );
      return true;
    }

    const matchingPositions: number[] = [];
    view.state.doc.forEach((node, offset) => {
      if (node.eq(dragState.sourceNode)) matchingPositions.push(offset);
    });

    if (matchingPositions.length !== 1) {
      if (view.state.doc.textContent.length === 0 && dragState.sourceNode.textContent.length > 0) {
        if (transientEmptyDragTimer === null) {
          transientEmptyDragTimer = setTimeout(() => {
            transientEmptyDragTimer = null;
            if (pointerDragState === dragState && activeView === view) {
              finishPointerDrag(view, false);
            }
          }, TRANSIENT_EMPTY_SYNC_GRACE_MS);
        }
        return false;
      }
      clearTransientEmptyDragTimer();
      finishPointerDrag(view, false);
      return false;
    }

    clearTransientEmptyDragTimer();
    dragState.sourcePos = matchingPositions[0];
    dragState.startDoc = view.state.doc;
    dragState.slice = view.state.doc.slice(
      dragState.sourcePos,
      dragState.sourcePos + dragState.sourceNode.nodeSize,
    );
    return true;
  }

  function beginPointerLikeDrag(
    editorView: EditorView,
    event: MouseEvent,
    pointerId: number | null,
  ) {
    if (event.button !== 0 || activeBlockPos < 0) return;

    const sourceNode = editorView.state.doc.nodeAt(activeBlockPos);
    if (!isDraggableTopLevelBlock(sourceNode)) return;

    event.preventDefault();
    event.stopPropagation();

    pointerDragState = {
      lastDropPos: null,
      pointerId,
      slice: editorView.state.doc.slice(activeBlockPos, activeBlockPos + sourceNode.nodeSize),
      startDoc: editorView.state.doc,
      sourceNode,
      sourcePos: activeBlockPos,
      startX: event.clientX,
      startY: event.clientY,
      started: false,
    };

    menuFrozen = true;
    setDragHandleActive(true);
    previousBodyCursor ??= document.body.style.cursor;
    document.body.style.cursor = "grabbing";
  }

  function handleDragMove(editorView: EditorView, event: MouseEvent) {
    const dragState = pointerDragState;
    if (!dragState) return;

    event.preventDefault();
    if (!refreshPointerDragStateForCurrentDoc(editorView)) return;
    const distance = Math.hypot(event.clientX - dragState.startX, event.clientY - dragState.startY);
    if (!dragState.started) {
      if (distance < POINTER_DRAG_THRESHOLD_PX) return;
      dragState.started = true;
      editorView.focus();
      const tr = editorView.state.tr.setSelection(
        NodeSelection.create(editorView.state.doc, dragState.sourcePos),
      );
      editorView.dispatch(tr);
      const sourceDom = editorView.nodeDOM(dragState.sourcePos);
      createDragPreview(
        dragState.sourceNode.textContent,
        sourceDom instanceof HTMLElement ? sourceDom : null,
      );
    }

    positionDragPreview(event);
    const nextDropPos = blockDropPosFromPointer(editorView, event, dragState.slice);
    dragState.lastDropPos = nextDropPos;
    if (nextDropPos === null) {
      cleanupDropCursor();
      return;
    }
    updateDropCursor(editorView, nextDropPos);
  }

  function handleDragEnd(editorView: EditorView, event: MouseEvent) {
    const dragState = pointerDragState;
    if (!dragState) return;

    event.preventDefault();
    if (!refreshPointerDragStateForCurrentDoc(editorView)) return;
    const currentDropPos = blockDropPosFromPointer(editorView, event, dragState.slice);
    finishPointerDrag(editorView, currentDropPos !== null, currentDropPos);
  }

  function scheduleHideHandle() {
    if (hideTimer !== null || handleContainsFocus()) return;
    hideTimer = setTimeout(() => {
      hideTimer = null;
      if (menuFrozen || handleContainsFocus()) return;
      setViewState({ visible: false });
    }, HIDE_HANDLE_DELAY_MS);
  }

  function blockPosFromDocPos(view: EditorView, pos: number): number {
    const $from = view.state.doc.resolve(pos);
    if ($from.depth <= 0) return -1;

    const blockPos = $from.before(1);
    if (isDraggableTopLevelBlock(view.state.doc.nodeAt(blockPos))) return blockPos;
    return -1;
  }

  function blockPosFromSelection(view: EditorView): number {
    const selection = view.state.selection;
    if (selection instanceof NodeSelection && isDraggableTopLevelBlock(selection.node)) {
      return selection.from;
    }
    return blockPosFromDocPos(view, view.state.selection.from);
  }

  function firstLineRect(view: EditorView, blockPos: number, dom: HTMLElement): DOMRect {
    const node = view.state.doc.nodeAt(blockPos);
    if (!node) return dom.getBoundingClientRect();

    const anchorPos =
      node.nodeSize > 1
        ? Math.min(blockPos + 1, view.state.doc.content.size)
        : Math.min(blockPos, view.state.doc.content.size);
    try {
      const coords = view.coordsAtPos(anchorPos);
      const height = Math.max(1, coords.bottom - coords.top);
      return new DOMRect(coords.left, coords.top, Math.max(1, coords.right - coords.left), height);
    } catch {
      return dom.getBoundingClientRect();
    }
  }

  function positionHandle(view: EditorView, blockPos: number): boolean {
    if (!handleEl) return false;

    const node = view.state.doc.nodeAt(blockPos);
    if (!node) {
      hideHandle();
      return false;
    }
    if (!(view.state.doc.textContent.length === 0 && activeBlockNode?.textContent.length)) {
      activeBlockNode = node;
    }

    const dom = view.nodeDOM(blockPos);
    if (!dom || !(dom instanceof HTMLElement)) {
      hideHandle();
      return false;
    }

    const container = view.dom.parentElement;
    if (!container) {
      hideHandle();
      return false;
    }

    const containerRect = container.getBoundingClientRect();
    const blockRect = dom.getBoundingClientRect();
    const lineRect = firstLineRect(view, blockPos, dom);
    const handleWidth = handleEl.offsetWidth || HANDLE_BUTTON_SIZE * 2 + 4 + HANDLE_BRIDGE_WIDTH;
    const minLeft = container.scrollLeft + 4;
    const maxLeft = container.scrollLeft + container.clientWidth - handleWidth - 4;
    const anchorLeft = lineRect.left - containerRect.left + container.scrollLeft;
    const naturalLeft = anchorLeft - handleWidth;
    if (maxLeft < minLeft || naturalLeft < minLeft) {
      hideHandle();
      return false;
    }
    const handleLeft = Math.min(naturalLeft, maxLeft);
    const measuredLineHeight = Math.max(1, lineRect.bottom - lineRect.top);
    const cssLineHeight = Number.parseFloat(getComputedStyle(dom).lineHeight);
    const lineHeight = Math.max(
      HANDLE_BUTTON_SIZE,
      measuredLineHeight,
      Number.isFinite(cssLineHeight) ? cssLineHeight : 0,
    );
    const anchorTop = lineRect.top - containerRect.top + container.scrollTop;
    const blockTop = blockRect.top - containerRect.top + container.scrollTop;
    const handleTop = Math.max(
      blockTop,
      anchorTop - Math.max(0, (lineHeight - measuredLineHeight) / 2),
    );

    setViewState({
      height: lineHeight,
      left: handleLeft,
      top: handleTop,
      visible: true,
    });
    return true;
  }

  function showHandle(view: EditorView, blockPos: number): boolean {
    activeBlockPos = blockPos;
    return positionHandle(view, blockPos);
  }

  function showHandleForSelection(view: EditorView): boolean {
    if (!view.hasFocus() && !handleContainsFocus()) return false;
    const blockPos = blockPosFromSelection(view);
    if (blockPos < 0) {
      hideHandle();
      return false;
    }
    return showHandle(view, blockPos);
  }

  function refreshVisibleHandle() {
    if (activeBlockPos < 0 || !viewState.visible || !activeView) return;
    positionHandle(activeView, activeBlockPos);
  }

  function finishDrag() {
    clearTransientEmptyDragTimer();
    menuFrozen = false;
    setDragHandleActive(false);
    cleanupDragPreview();
    cleanupDropCursor();
    if (previousBodyCursor !== null) {
      document.body.style.cursor = previousBodyCursor;
      previousBodyCursor = null;
    }
    hideHandle();
  }

  function moveBlockToDropPos(
    editorView: EditorView,
    sourcePos: number,
    sourceNode: ProseMirrorNode,
    dropPos: number,
  ): boolean {
    const sourceEnd = sourcePos + sourceNode.nodeSize;
    if (dropPos >= sourcePos && dropPos <= sourceEnd) return false;

    const state = editorView.state;
    const currentSourceNode = state.doc.nodeAt(sourcePos);
    if (!currentSourceNode?.eq(sourceNode)) return false;

    let insertPos = dropPos;
    if (insertPos > sourcePos) insertPos -= sourceNode.nodeSize;

    try {
      let tr = state.tr.delete(sourcePos, sourceEnd);
      insertPos = Math.max(0, Math.min(insertPos, tr.doc.content.size));
      tr = tr.insert(insertPos, sourceNode);
      tr = tr.setSelection(NodeSelection.create(tr.doc, insertPos)).scrollIntoView();
      editorView.focus();
      editorView.dispatch(tr);
    } catch {
      return false;
    }

    return true;
  }

  function finishPointerDrag(
    editorView: EditorView,
    shouldDrop: boolean,
    currentDropPos?: number | null,
  ) {
    const dragState = pointerDragState;
    pointerDragState = null;
    const dropPos = currentDropPos ?? dragState?.lastDropPos ?? null;

    if (
      shouldDrop &&
      dragState?.started &&
      dropPos !== null &&
      (editorView.state.doc.eq(dragState.startDoc) || currentDropPos !== undefined)
    ) {
      moveBlockToDropPos(editorView, dragState.sourcePos, dragState.sourceNode, dropPos);
    }

    finishDrag();
  }

  function finishNativeDragOrDrop() {
    if (pointerDragState) return;
    finishDrag();
  }

  function insertBlockBelow(editorView: EditorView): boolean {
    if (activeBlockPos < 0) return false;

    const state = editorView.state;
    const node = state.doc.nodeAt(activeBlockPos);
    if (!node) return false;

    const after = activeBlockPos + node.nodeSize;
    const paragraph = state.schema.nodes.paragraph.create();
    const tr = state.tr.insert(after, paragraph);
    tr.setSelection(TextSelection.create(tr.doc, after + 1));
    editorView.dispatch(tr);
    editorView.focus();
    return true;
  }

  function isTransientEmptySyncDoc(editorView: EditorView): boolean {
    const currentNode = activeBlockPos >= 0 ? editorView.state.doc.nodeAt(activeBlockPos) : null;
    return (
      editorView.state.doc.textContent.length === 0 &&
      !!activeBlockNode &&
      activeBlockNode.textContent.length > 0 &&
      (!currentNode || !currentNode.eq(activeBlockNode))
    );
  }

  function openBlockMenuBelow(editorView: EditorView, retryCount = 0) {
    if (activeBlockPos < 0) return;
    if (isTransientEmptySyncDoc(editorView)) {
      if (retryCount < 4) {
        requestAnimationFrame(() => {
          if (activeView === editorView) openBlockMenuBelow(editorView, retryCount + 1);
        });
      }
      return;
    }
    if (options.openBlockMenuBelow?.(editorView, activeBlockPos)) return;
    insertBlockBelow(editorView);
  }

  function updateHandleFromPointer(view: EditorView, event: MouseEvent): boolean {
    if (menuFrozen || !handleEl) return false;

    const editorRect = view.dom.getBoundingClientRect();
    const clampedX = Math.min(Math.max(event.clientX, editorRect.left + 1), editorRect.right - 1);

    const pos = view.posAtCoords({
      left: clampedX,
      top: event.clientY,
    });
    if (!pos) {
      hideHandle();
      return false;
    }

    const $pos = view.state.doc.resolve(pos.pos);
    const depth = $pos.depth;
    if (depth === 0) {
      hideHandle();
      return false;
    }

    const blockPos = blockPosFromDocPos(view, pos.pos);
    if (blockPos < 0) {
      hideHandle();
      return false;
    }
    if (blockPos === activeBlockPos && viewState.visible) {
      positionHandle(view, blockPos);
      return false;
    }

    showHandle(view, blockPos);
    return false;
  }

  return new Plugin({
    view(editorView: EditorView) {
      activeView = editorView;
      const container = editorView.dom.parentElement!;
      const resizeObserver =
        typeof ResizeObserver !== "undefined" ? new ResizeObserver(refreshVisibleHandle) : null;
      resizeObserver?.observe(container);
      resizeObserver?.observe(editorView.dom);
      container.addEventListener("scroll", refreshVisibleHandle, { passive: true });
      window.addEventListener("resize", refreshVisibleHandle);

      const controller: BlockHandleViewController = {
        attachHandleElement(element) {
          handleEl = element;
          refreshVisibleHandle();
        },
        beginMouseDrag(event) {
          if (pointerDragState) {
            event.preventDefault();
            event.stopPropagation();
            return;
          }
          beginPointerLikeDrag(editorView, event, null);
        },
        beginNativeDrag(e) {
          if (pointerDragState) {
            e.preventDefault();
            e.stopPropagation();
            return;
          }
          if (activeBlockPos < 0) return;
          if (!e.dataTransfer) return;

          const state = editorView.state;
          const $pos = state.doc.resolve(activeBlockPos);
          const node = $pos.nodeAfter;
          if (!isDraggableTopLevelBlock(node)) return;

          menuFrozen = true;
          setDragHandleActive(true);

          const tr = state.tr.setSelection(NodeSelection.create(state.doc, activeBlockPos));
          editorView.dispatch(tr);

          const slice = editorView.state.selection.content();
          e.dataTransfer?.setData("text/plain", node.textContent);
          e.dataTransfer.effectAllowed = "move";
          const sourceDom = editorView.nodeDOM(activeBlockPos);
          const dragPreview = createDragPreview(
            node.textContent,
            sourceDom instanceof HTMLElement ? sourceDom : null,
          );
          e.dataTransfer.setDragImage(dragPreview, 12, 12);
          setTimeout(cleanupDragPreview, 0);

          editorView.dragging = {
            slice,
            move: true,
          };
        },
        beginPointerDrag(event) {
          if (pointerDragState) return;
          beginPointerLikeDrag(editorView, event, event.pointerId);
          if (
            event.currentTarget instanceof Element &&
            typeof event.currentTarget.setPointerCapture === "function"
          ) {
            event.currentTarget.setPointerCapture(event.pointerId);
          }
        },
        finishDrag,
        getState() {
          return viewState;
        },
        openBlockMenu(event) {
          event?.preventDefault();
          openBlockMenuBelow(editorView);
        },
        refreshVisibleHandle,
        setMenuFrozen(frozen) {
          menuFrozen = frozen;
          if (frozen) {
            clearHideTimer();
            return;
          }
          if (!editorView.hasFocus()) scheduleHideHandle();
        },
        subscribe(listener) {
          subscribers.add(listener);
          listener(viewState);
          return () => subscribers.delete(listener);
        },
      };

      handleView = options.createHandleView(editorView, controller);

      const handlePointerMove = (event: PointerEvent) => {
        const dragState = pointerDragState;
        if (!dragState || dragState.pointerId === null) return;
        if (dragState.pointerId !== event.pointerId) return;

        handleDragMove(editorView, event);
      };

      const handlePointerUp = (event: PointerEvent) => {
        const dragState = pointerDragState;
        if (!dragState || dragState.pointerId === null) return;
        if (dragState.pointerId !== event.pointerId) return;
        if (event.pointerType === "mouse" || event.pointerType === "") return;
        handleDragEnd(editorView, event);
      };

      const handleMouseMove = (event: MouseEvent) => {
        if (!pointerDragState) return;
        handleDragMove(editorView, event);
      };

      const handleMouseUp = (event: MouseEvent) => {
        if (!pointerDragState) return;
        handleDragEnd(editorView, event);
      };

      const handlePointerCancel = (event: PointerEvent) => {
        const dragState = pointerDragState;
        if (!dragState || dragState.pointerId !== event.pointerId) return;
        if (event.pointerType === "mouse" || event.pointerType === "") return;
        finishPointerDrag(editorView, false);
      };

      document.addEventListener("pointermove", handlePointerMove, true);
      document.addEventListener("pointerup", handlePointerUp, true);
      document.addEventListener("pointercancel", handlePointerCancel, true);
      document.addEventListener("mousemove", handleMouseMove, true);
      document.addEventListener("mouseup", handleMouseUp, true);

      editorView.dom.addEventListener("drop", finishNativeDragOrDrop);
      editorView.dom.addEventListener("dragend", finishNativeDragOrDrop);

      return {
        update(nextView, prevState) {
          activeView = nextView;
          handleView?.update?.(nextView, prevState);
          if (!refreshPointerDragStateForCurrentDoc(nextView)) return;
          if (!showHandleForSelection(nextView)) refreshVisibleHandle();
        },
        destroy() {
          finishDrag();
          handleView?.destroy?.();
          handleView = null;
          container.removeEventListener("scroll", refreshVisibleHandle);
          window.removeEventListener("resize", refreshVisibleHandle);
          document.removeEventListener("pointermove", handlePointerMove, true);
          document.removeEventListener("pointerup", handlePointerUp, true);
          document.removeEventListener("pointercancel", handlePointerCancel, true);
          document.removeEventListener("mousemove", handleMouseMove, true);
          document.removeEventListener("mouseup", handleMouseUp, true);
          editorView.dom.removeEventListener("drop", finishNativeDragOrDrop);
          editorView.dom.removeEventListener("dragend", finishNativeDragOrDrop);
          resizeObserver?.disconnect();
          clearHideTimer();
          clearTransientEmptyDragTimer();
          pointerDragState = null;
          activeBlockNode = null;
          handleEl = null;
          activeView = null;
          subscribers.clear();
        },
      };
    },

    props: {
      handleDOMEvents: {
        mousemove(view, event) {
          return updateHandleFromPointer(view, event);
        },

        pointermove(view, event) {
          return updateHandleFromPointer(view, event);
        },

        focus(view, _event) {
          showHandleForSelection(view);
          return false;
        },

        blur(view, _event) {
          queueMicrotask(() => {
            if (!view.hasFocus() && !handleContainsFocus()) hideHandle();
          });
          return false;
        },

        keydown(view, _event) {
          showHandleForSelection(view);
          return false;
        },

        mouseleave(view, event) {
          if (targetIsHandle(event.relatedTarget)) {
            clearHideTimer();
            menuFrozen = true;
            return false;
          }
          if (!menuFrozen && handleEl && !view.hasFocus()) {
            scheduleHideHandle();
          }
          return false;
        },
      },
    },
  });
}
