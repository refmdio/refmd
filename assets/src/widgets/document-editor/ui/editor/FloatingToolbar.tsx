import { createEffect, type Component } from "solid-js";
import { Portal } from "solid-js/web";
import type { EditorView } from "prosemirror-view";
import type { Schema } from "prosemirror-model";
import { computePosition, offset, flip, shift } from "@floating-ui/dom";
import {
  BoldIcon,
  CodeIcon,
  Heading1Icon,
  Heading2Icon,
  ItalicIcon,
  LinkIcon,
  ListIcon,
  ListOrderedIcon,
  ListTodoIcon,
  PilcrowIcon,
  QuoteIcon,
  StrikethroughIcon,
  type LucideProps,
} from "lucide-solid";
import {
  isFloatingToolbarActionActive,
  runFloatingToolbarAction,
  type FloatingToolbarActionId,
} from "./floating-toolbar-commands";
import { Button } from "@/shared/ui/button";

interface ToolbarButtonDef {
  id: FloatingToolbarActionId;
  label: string;
  icon: Component<LucideProps>;
}

const MARK_BUTTONS: ToolbarButtonDef[] = [
  { id: "strong", label: "Bold", icon: BoldIcon },
  { id: "em", label: "Italic", icon: ItalicIcon },
  { id: "strikethrough", label: "Strikethrough", icon: StrikethroughIcon },
  { id: "code", label: "Code", icon: CodeIcon },
  { id: "link", label: "Link", icon: LinkIcon },
];

const BLOCK_BUTTONS: ToolbarButtonDef[] = [
  { id: "paragraph", label: "Paragraph", icon: PilcrowIcon },
  { id: "heading1", label: "Heading 1", icon: Heading1Icon },
  { id: "heading2", label: "Heading 2", icon: Heading2Icon },
  { id: "blockquote", label: "Quote", icon: QuoteIcon },
  { id: "bullet_list", label: "Bulleted list", icon: ListIcon },
  { id: "ordered_list", label: "Numbered list", icon: ListOrderedIcon },
  { id: "task_list", label: "Task list", icon: ListTodoIcon },
];

interface FloatingToolbarProps {
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

    void computePosition(virtualEl, toolbar, {
      placement: "top",
      middleware: [offset(8), flip(), shift({ padding: 8 })],
    }).then(({ x, y }) => {
      toolbar.style.left = `${x}px`;
      toolbar.style.top = `${y}px`;
    });
  });

  const availableMarkButtons = () =>
    MARK_BUTTONS.filter((button) =>
      button.id === "link" ? props.schema.marks.link : props.schema.marks[button.id],
    );
  const availableBlockButtons = () =>
    BLOCK_BUTTONS.filter((button) => {
      switch (button.id) {
        case "paragraph":
          return props.schema.nodes.paragraph;
        case "heading1":
        case "heading2":
          return props.schema.nodes.heading;
        case "blockquote":
          return props.schema.nodes.blockquote;
        case "bullet_list":
          return props.schema.nodes.bullet_list;
        case "ordered_list":
          return props.schema.nodes.ordered_list;
        case "task_list":
          return props.schema.nodes.bullet_list && props.schema.nodes.list_item;
        default:
          return false;
      }
    });

  function runAction(button: ToolbarButtonDef) {
    let href: string | null | undefined;
    if (button.id === "link" && !isFloatingToolbarActionActive(props.view.state, "link")) {
      href = window.prompt("Link URL")?.trim();
      if (!href) return;
    }

    const handled = runFloatingToolbarAction(props.view, button.id, { href });
    if (handled) props.view.focus();
  }

  return (
    <Portal>
      <div
        ref={(el) => {
          toolbarEl = el;
        }}
        class="refmd-floating-toolbar fixed z-40 flex items-center gap-0.5 rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md"
        data-refmd-editor-chrome="floating-toolbar"
      >
        {[...availableMarkButtons(), ...availableBlockButtons()].map((btn, index) => {
          const Icon = btn.icon;
          const active = (() => {
            void props.selectionVersion;
            return isFloatingToolbarActionActive(props.view.state, btn.id);
          })();

          return (
            <>
              <ShowSeparator when={index === availableMarkButtons().length} />
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                class={`size-7 rounded-sm p-0 ${
                  active
                    ? "bg-foreground text-background hover:bg-foreground/90 hover:text-background"
                    : "hover:bg-accent hover:text-accent-foreground"
                }`}
                aria-label={btn.label}
                title={btn.label}
                onMouseDown={(e) => {
                  e.preventDefault();
                  runAction(btn);
                }}
              >
                <Icon class="size-3.5" />
              </Button>
            </>
          );
        })}
      </div>
    </Portal>
  );
}

function ShowSeparator(props: { when: boolean }) {
  return props.when ? <div class="mx-1 h-5 w-px bg-border/70" aria-hidden="true" /> : null;
}
