import { Plugin, Selection, NodeSelection } from "prosemirror-state";
import type { EditorView } from "prosemirror-view";

const PLUS_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`;

const GRIP_SVG = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="5" r="1.5"/><circle cx="15" cy="5" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="19" r="1.5"/><circle cx="15" cy="19" r="1.5"/></svg>`;

export function blockHandlePlugin(): Plugin {
  let handleEl: HTMLDivElement | null = null;
  let hoveredBlockPos = -1;
  let menuFrozen = false;

  return new Plugin({
    view(editorView: EditorView) {
      handleEl = document.createElement("div");
      handleEl.className = "pm-block-handle";

      const addBtn = document.createElement("button");
      addBtn.type = "button";
      addBtn.className = "pm-block-handle-add";
      addBtn.innerHTML = PLUS_SVG;
      addBtn.title = "Add block below";

      const dragBtn = document.createElement("button");
      dragBtn.type = "button";
      dragBtn.className = "pm-block-handle-drag";
      dragBtn.draggable = true;
      dragBtn.innerHTML = GRIP_SVG;
      dragBtn.title = "Drag to move";

      handleEl.appendChild(addBtn);
      handleEl.appendChild(dragBtn);

      const container = editorView.dom.parentElement!;
      container.appendChild(handleEl);

      addBtn.addEventListener("mousedown", (e) => {
        e.preventDefault();
        if (hoveredBlockPos < 0) return;

        const state = editorView.state;
        const $pos = state.doc.resolve(hoveredBlockPos);
        const after = $pos.after(1);
        const paragraph = state.schema.nodes.paragraph.create();
        const tr = state.tr.insert(after, paragraph);
        tr.setSelection(Selection.near(tr.doc.resolve(after + 1)));
        editorView.dispatch(tr);
        editorView.focus();
      });

      dragBtn.addEventListener("dragstart", (e) => {
        if (hoveredBlockPos < 0) return;
        menuFrozen = true;

        const state = editorView.state;
        const $pos = state.doc.resolve(hoveredBlockPos);
        const node = $pos.nodeAfter;
        if (!node) return;

        const tr = state.tr.setSelection(NodeSelection.create(state.doc, hoveredBlockPos));
        editorView.dispatch(tr);

        const slice = editorView.state.selection.content();
        e.dataTransfer?.setData("text/plain", node.textContent);
        e.dataTransfer!.effectAllowed = "move";

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
        menuFrozen = true;
      });
      handleEl.addEventListener("mouseleave", () => {
        menuFrozen = false;
      });

      return {
        update() {},
        destroy() {
          handleEl?.remove();
          handleEl = null;
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
            handleEl.classList.remove("visible");
            return false;
          }

          const $pos = view.state.doc.resolve(pos.pos);
          const depth = $pos.depth;
          if (depth === 0) {
            handleEl.classList.remove("visible");
            return false;
          }

          const blockPos = $pos.before(1);
          if (blockPos === hoveredBlockPos && handleEl.classList.contains("visible")) {
            return false;
          }

          hoveredBlockPos = blockPos;
          const node = view.state.doc.nodeAt(blockPos);
          if (!node) {
            handleEl.classList.remove("visible");
            return false;
          }

          const dom = view.nodeDOM(blockPos);
          if (!dom || !(dom instanceof HTMLElement)) {
            handleEl.classList.remove("visible");
            return false;
          }

          const container = view.dom.parentElement!;
          const containerRect = container.getBoundingClientRect();
          const blockRect = dom.getBoundingClientRect();

          handleEl.style.top = `${blockRect.top - containerRect.top}px`;
          const lineHeight = parseFloat(getComputedStyle(dom).lineHeight) || 24;
          handleEl.style.paddingTop = `${(lineHeight - 20) / 2}px`;

          handleEl.classList.add("visible");
          return false;
        },

        keydown(_view, _event) {
          if (handleEl) {
            handleEl.classList.remove("visible");
          }
          return false;
        },

        mouseleave(_view, _event) {
          if (!menuFrozen && handleEl) {
            handleEl.classList.remove("visible");
          }
          return false;
        },
      },
    },
  });
}
