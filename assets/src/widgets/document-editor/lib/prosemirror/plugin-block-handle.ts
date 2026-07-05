import { NodeSelection, Plugin, Selection } from "prosemirror-state";
import type { EditorView } from "prosemirror-view";

const PLUS_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`;

const GRIP_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="5" r="1.5"/><circle cx="15" cy="5" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="19" r="1.5"/><circle cx="15" cy="19" r="1.5"/></svg>`;

const HANDLE_BUTTON_SIZE = 32;
const HIDE_HANDLE_DELAY_MS = 140;

const ALLOWED_HTML = new Set([PLUS_SVG, GRIP_SVG]);
const ttPolicy =
  globalThis.trustedTypes?.createPolicy("refmd-block-handle", {
    createHTML(input: string) {
      if (ALLOWED_HTML.has(input)) return input;
      throw new TypeError("Unexpected HTML in block-handle-plugin");
    },
  }) ?? null;

function setStaticHtml(el: HTMLElement, html: string): void {
  if (ttPolicy) {
    el.innerHTML = ttPolicy.createHTML(html) as unknown as string;
  } else {
    el.innerHTML = html;
  }
}

export function blockHandlePlugin(): Plugin {
  let handleEl: HTMLDivElement | null = null;
  let activeBlockPos = -1;
  let menuFrozen = false;
  let activeView: EditorView | null = null;
  let hideTimer: ReturnType<typeof setTimeout> | null = null;

  function clearHideTimer() {
    if (hideTimer === null) return;
    clearTimeout(hideTimer);
    hideTimer = null;
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
    handleEl?.classList.remove("visible");
  }

  function scheduleHideHandle() {
    if (hideTimer !== null || handleContainsFocus()) return;
    hideTimer = setTimeout(() => {
      hideTimer = null;
      if (menuFrozen || handleContainsFocus()) return;
      handleEl?.classList.remove("visible");
    }, HIDE_HANDLE_DELAY_MS);
  }

  function blockPosFromDocPos(view: EditorView, pos: number): number {
    const $from = view.state.doc.resolve(pos);
    for (let depth = $from.depth; depth > 0; depth--) {
      if ($from.node(depth).isBlock) return $from.before(depth);
    }
    return -1;
  }

  function blockPosFromSelection(view: EditorView): number {
    return blockPosFromDocPos(view, view.state.selection.from);
  }

  function positionHandle(view: EditorView, blockPos: number): boolean {
    if (!handleEl) return false;

    const node = view.state.doc.nodeAt(blockPos);
    if (!node) {
      hideHandle();
      return false;
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
    const handleWidth = handleEl.offsetWidth || HANDLE_BUTTON_SIZE * 2 + 4;
    const gap = 8;
    const minLeft = container.scrollLeft + 4;
    const maxLeft = container.scrollLeft + container.clientWidth - handleWidth - 4;
    const blockLeft = blockRect.left - containerRect.left + container.scrollLeft;
    const handleLeft = Math.max(minLeft, Math.min(blockLeft - handleWidth - gap, maxLeft));

    handleEl.style.left = `${handleLeft}px`;
    handleEl.style.top = `${blockRect.top - containerRect.top + container.scrollTop}px`;

    const lineHeight = parseFloat(getComputedStyle(dom).lineHeight) || 24;
    handleEl.style.paddingTop = `${Math.max(0, (lineHeight - HANDLE_BUTTON_SIZE) / 2)}px`;
    handleEl.classList.add("visible");
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
    if (activeBlockPos < 0 || !handleEl?.classList.contains("visible") || !activeView) return;
    positionHandle(activeView, activeBlockPos);
  }

  function insertBlockBelow(editorView: EditorView) {
    if (activeBlockPos < 0) return;

    const state = editorView.state;
    const node = state.doc.nodeAt(activeBlockPos);
    if (!node) return;

    const after = activeBlockPos + node.nodeSize;
    const paragraph = state.schema.nodes.paragraph.create();
    const tr = state.tr.insert(after, paragraph);
    tr.setSelection(Selection.near(tr.doc.resolve(after + 1)));
    editorView.dispatch(tr);
    editorView.focus();
  }

  return new Plugin({
    view(editorView: EditorView) {
      activeView = editorView;
      handleEl = document.createElement("div");
      handleEl.className = "pm-block-handle";

      const addBtn = document.createElement("button");
      addBtn.type = "button";
      addBtn.className = "pm-block-handle-add";
      setStaticHtml(addBtn, PLUS_SVG);
      addBtn.setAttribute("aria-label", "Add block below");
      addBtn.title = "Add block below";

      const dragBtn = document.createElement("button");
      dragBtn.type = "button";
      dragBtn.className = "pm-block-handle-drag";
      dragBtn.draggable = true;
      setStaticHtml(dragBtn, GRIP_SVG);
      dragBtn.setAttribute("aria-label", "Drag to move block");
      dragBtn.title = "Drag to move";

      handleEl.appendChild(addBtn);
      handleEl.appendChild(dragBtn);

      const container = editorView.dom.parentElement!;
      container.appendChild(handleEl);
      const resizeObserver =
        typeof ResizeObserver !== "undefined" ? new ResizeObserver(refreshVisibleHandle) : null;
      resizeObserver?.observe(container);
      resizeObserver?.observe(editorView.dom);
      container.addEventListener("scroll", refreshVisibleHandle, { passive: true });
      window.addEventListener("resize", refreshVisibleHandle);

      addBtn.addEventListener("mousedown", (e) => {
        e.preventDefault();
      });
      addBtn.addEventListener("click", (e) => {
        e.preventDefault();
        insertBlockBelow(editorView);
      });

      dragBtn.addEventListener("dragstart", (e) => {
        if (activeBlockPos < 0) return;
        if (!e.dataTransfer) return;
        menuFrozen = true;

        const state = editorView.state;
        const $pos = state.doc.resolve(activeBlockPos);
        const node = $pos.nodeAfter;
        if (!node) return;

        const tr = state.tr.setSelection(NodeSelection.create(state.doc, activeBlockPos));
        editorView.dispatch(tr);

        const slice = editorView.state.selection.content();
        e.dataTransfer?.setData("text/plain", node.textContent);
        e.dataTransfer.effectAllowed = "move";

        editorView.dragging = {
          slice,
          move: true,
        };
      });

      dragBtn.addEventListener("dragend", () => {
        menuFrozen = false;
        if (handleEl) handleEl.classList.remove("visible");
      });

      handleEl.addEventListener("mouseenter", () => {
        clearHideTimer();
        menuFrozen = true;
      });
      handleEl.addEventListener("mouseleave", () => {
        menuFrozen = false;
        if (!editorView.hasFocus()) scheduleHideHandle();
      });
      handleEl.addEventListener("focusin", () => {
        clearHideTimer();
        menuFrozen = true;
        refreshVisibleHandle();
      });
      handleEl.addEventListener("focusout", () => {
        menuFrozen = false;
        queueMicrotask(() => {
          if (!editorView.hasFocus() && !handleContainsFocus()) hideHandle();
        });
      });

      return {
        update() {
          if (!showHandleForSelection(editorView)) refreshVisibleHandle();
        },
        destroy() {
          container.removeEventListener("scroll", refreshVisibleHandle);
          window.removeEventListener("resize", refreshVisibleHandle);
          resizeObserver?.disconnect();
          clearHideTimer();
          handleEl?.remove();
          handleEl = null;
          activeView = null;
        },
      };
    },

    props: {
      handleDOMEvents: {
        mousemove(view, event) {
          if (menuFrozen || !handleEl) return false;

          const editorRect = view.dom.getBoundingClientRect();
          const clampedX = Math.min(
            Math.max(event.clientX, editorRect.left + 1),
            editorRect.right - 1,
          );

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
          if (blockPos === activeBlockPos && handleEl.classList.contains("visible")) {
            positionHandle(view, blockPos);
            return false;
          }

          showHandle(view, blockPos);
          return false;
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
