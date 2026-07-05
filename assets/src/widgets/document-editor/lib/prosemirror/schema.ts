import { Schema } from "prosemirror-model";
import { schema as basicSchema } from "prosemirror-schema-basic";
import { addListNodes } from "prosemirror-schema-list";
import { tableNodes } from "prosemirror-tables";

let nodes = addListNodes(basicSchema.spec.nodes, "paragraph block*", "block");

nodes = nodes.update("list_item", {
  ...nodes.get("list_item")!,
  attrs: { checked: { default: null } },
  parseDOM: [
    {
      tag: "li",
      getAttrs(dom: HTMLElement) {
        const dataChecked = dom.getAttribute("data-checked");
        if (dataChecked === "true") return { checked: true };
        if (dataChecked === "false") return { checked: false };

        const checkbox = dom.querySelector<HTMLInputElement>('input[type="checkbox"]');
        if (checkbox) return { checked: checkbox.checked };

        return { checked: null };
      },
    },
  ],
  toDOM(node) {
    const checked = node.attrs.checked;
    if (typeof checked !== "boolean") return ["li", 0];

    const inputAttrs: Record<string, string> = {
      "aria-label": checked ? "Completed task" : "Incomplete task",
      contenteditable: "false",
      tabindex: "-1",
      type: "checkbox",
    };
    if (checked) inputAttrs.checked = "";

    return [
      "li",
      { "data-checked": checked ? "true" : "false" },
      ["input", inputAttrs],
      ["div", { class: "refmd-task-list-content" }, 0],
    ];
  },
});

nodes = nodes.append(
  tableNodes({
    tableGroup: "block",
    cellContent: "block+",
    cellAttributes: {},
  }),
);

// Override hard_break: filter ProseMirror-trailingBreak
nodes = nodes.update("hard_break", {
  ...basicSchema.spec.nodes.get("hard_break")!,
  parseDOM: [
    {
      tag: "br",
      getAttrs(dom: HTMLElement) {
        return dom.classList.contains("ProseMirror-trailingBreak") ? false : null;
      },
    },
  ],
});

// Override image: add XSS sanitization in toDOM
nodes = nodes.update("image", {
  ...basicSchema.spec.nodes.get("image")!,
  toDOM(node) {
    const { src, alt, title } = node.attrs;
    const safeSrc =
      /^(https:|blob:)/i.test(src) || (/^data:image\//i.test(src) && !/^data:image\/svg/i.test(src))
        ? src
        : undefined;
    return ["img", { src: safeSrc, alt, title }];
  },
});

nodes = nodes.update("code_block", {
  ...basicSchema.spec.nodes.get("code_block")!,
  attrs: { language: { default: null } },
  parseDOM: [
    {
      tag: "pre",
      preserveWhitespace: "full",
      getAttrs(dom: HTMLElement) {
        const code = dom.querySelector("code");
        return { language: code?.getAttribute("data-language") ?? null };
      },
    },
  ],
  toDOM(node) {
    const language = typeof node.attrs.language === "string" ? node.attrs.language : null;
    return ["pre", ["code", language ? { "data-language": language } : {}, 0]];
  },
});

let marks = basicSchema.spec.marks;

// Override link: add XSS sanitization + rel attr
marks = marks.update("link", {
  ...basicSchema.spec.marks.get("link")!,
  toDOM(node) {
    const { href, title } = node.attrs;
    const safeHref = /^(https|mailto):/i.test(href) ? href : undefined;
    return ["a", { href: safeHref, title, rel: "noopener noreferrer" }, 0];
  },
});

// Add strikethrough mark
marks = marks.addToEnd("strikethrough", {
  parseDOM: [{ tag: "s" }, { tag: "del" }, { style: "text-decoration=line-through" }],
  toDOM() {
    return ["del", 0];
  },
});

export const markdownSchema = new Schema({ nodes, marks });
