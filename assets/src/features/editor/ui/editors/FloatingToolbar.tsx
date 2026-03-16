import { createEffect } from "solid-js";
import { Portal } from "solid-js/web";
import type { EditorView } from "prosemirror-view";
import type { Schema, MarkType } from "prosemirror-model";
import { toggleMark } from "prosemirror-commands";
import { computePosition, offset, flip, shift } from "@floating-ui/dom";

interface ToolbarButtonDef {
  mark: string;
  label: string;
  icon: string;
}

const BUTTONS: ToolbarButtonDef[] = [
  { mark: "strong", label: "Bold", icon: "B" },
  { mark: "em", label: "Italic", icon: "I" },
  { mark: "strikethrough", label: "Strikethrough", icon: "S" },
  { mark: "code", label: "Code", icon: "<>" },
];

function isMarkActive(state: EditorView["state"], markType: MarkType): boolean {
  const { from, $from, to, empty } = state.selection;
  if (empty) {
    return !!markType.isInSet(state.storedMarks || $from.marks());
  }
  return state.doc.rangeHasMark(from, to, markType);
}

export interface FloatingToolbarProps {
  view: EditorView;
  schema: Schema;
  selectionVersion: number;
}

export function FloatingToolbar(props: FloatingToolbarProps) {
  let toolbarEl: HTMLDivElement | undefined;

  createEffect(() => {
    void props.selectionVersion;
    const toolbar = toolbarEl;
    const view = props.view;
    if (!toolbar || !view) return;

    const { from, to, empty } = view.state.selection;
    if (empty) return;

    const virtualEl = {
      getBoundingClientRect: () => {
        const start = view.coordsAtPos(from);
        const end = view.coordsAtPos(to);
        return new DOMRect(start.left, start.top, end.right - start.left, end.bottom - start.top);
      },
    };

    computePosition(virtualEl, toolbar, {
      placement: "top",
      middleware: [offset(8), flip(), shift({ padding: 8 })],
    }).then(({ x, y }) => {
      toolbar.style.left = `${x}px`;
      toolbar.style.top = `${y}px`;
    });
  });

  const availableButtons = () => BUTTONS.filter((b) => props.schema.marks[b.mark]);

  return (
    <Portal>
      <div
        ref={(el) => {
          toolbarEl = el;
        }}
        class="fixed z-40 flex items-center gap-0.5 border border-border/60 bg-muted/60 p-1 shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]"
      >
        {availableButtons().map((btn) => {
          const markType = props.schema.marks[btn.mark];
          const active = (() => {
            void props.selectionVersion;
            return isMarkActive(props.view.state, markType);
          })();

          return (
            <button
              type="button"
              class={`flex size-7 items-center justify-center rounded-sm ${
                active
                  ? "bg-foreground text-background hover:bg-foreground/90 hover:text-background"
                  : "hover:bg-accent hover:text-accent-foreground"
              }`}
              title={btn.label}
              onMouseDown={(e) => {
                e.preventDefault();
                const cmd = toggleMark(markType);
                cmd(props.view.state, props.view.dispatch);
                props.view.focus();
              }}
            >
              <span
                class={`text-xs ${btn.mark === "strong" ? "font-bold" : ""} ${btn.mark === "em" ? "italic" : ""} ${btn.mark === "strikethrough" ? "line-through" : ""} ${btn.mark === "code" ? "font-mono text-[10px]" : ""}`}
              >
                {btn.icon}
              </span>
            </button>
          );
        })}
      </div>
    </Portal>
  );
}
