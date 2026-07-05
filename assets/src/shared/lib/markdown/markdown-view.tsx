import { For, type JSX } from "solid-js";
import type {
  BlockContent,
  Content,
  DefinitionContent,
  Delete,
  Emphasis,
  Heading,
  Image,
  InlineCode,
  Link,
  List,
  ListItem,
  Paragraph,
  PhrasingContent,
  Root,
  RootContent,
  Strong,
  Table,
  TableCell,
  TableRow,
  Text,
} from "mdast";
import { parseMarkdownRoot } from "./parse";
import "./markdown-surface.css";

export type MarkdownViewHeading = {
  id: string;
  level: number;
  title: string;
};

function slugify(value: string, index: number) {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9\u3040-\u30ff\u3400-\u9fff]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return slug ? `${slug}-${index}` : `heading-${index}`;
}

function headingId(heading: Heading, fallbackIndex: number) {
  return slugify(textFromInline(heading.children), heading.position?.start.line ?? fallbackIndex);
}

function textFromInline(children: PhrasingContent[]): string {
  return children
    .map((child) => {
      if (child.type === "text" || child.type === "inlineCode") return child.value;
      if ("children" in child) return textFromInline(child.children as PhrasingContent[]);
      if (child.type === "image") return child.alt ?? "";
      return "";
    })
    .join("");
}

function isSafeHref(value: string) {
  return /^(https|mailto):/i.test(value);
}

function isSafeImageSrc(value: string) {
  return (
    /^(https:|blob:)/i.test(value) ||
    (/^data:image\//i.test(value) && !/^data:image\/svg/i.test(value))
  );
}

function renderInline(node: PhrasingContent, index: () => number): JSX.Element {
  switch (node.type) {
    case "text":
      return (node as Text).value;
    case "strong":
      return <strong>{renderInlineChildren((node as Strong).children)}</strong>;
    case "emphasis":
      return <em>{renderInlineChildren((node as Emphasis).children)}</em>;
    case "delete":
      return <del>{renderInlineChildren((node as Delete).children)}</del>;
    case "inlineCode":
      return <code>{(node as InlineCode).value}</code>;
    case "link": {
      const link = node as Link;
      return (
        <a href={isSafeHref(link.url) ? link.url : undefined} title={link.title ?? undefined}>
          {renderInlineChildren(link.children)}
        </a>
      );
    }
    case "image": {
      const image = node as Image;
      return (
        <img
          src={isSafeImageSrc(image.url) ? image.url : undefined}
          alt={image.alt ?? ""}
          title={image.title ?? undefined}
        />
      );
    }
    case "break":
      return <br data-break-index={index()} />;
    default:
      return "";
  }
}

function renderInlineChildren(children: PhrasingContent[]) {
  return <For each={children}>{(child, index) => renderInline(child, index)}</For>;
}

function renderBlock(node: RootContent | Content | DefinitionContent, index: () => number) {
  switch (node.type) {
    case "paragraph": {
      const paragraph = node as Paragraph;
      return (
        <p>{paragraph.children.length === 0 ? <br /> : renderInlineChildren(paragraph.children)}</p>
      );
    }
    case "heading": {
      const heading = node as Heading;
      const id = headingId(heading, index());
      const children = renderInlineChildren(heading.children);

      if (heading.depth === 1) return <h1 id={id}>{children}</h1>;
      if (heading.depth === 2) return <h2 id={id}>{children}</h2>;
      if (heading.depth === 3) return <h3 id={id}>{children}</h3>;
      return <h4 id={id}>{children}</h4>;
    }
    case "blockquote":
      return <blockquote>{renderBlockChildren(node.children as BlockContent[])}</blockquote>;
    case "code":
      return (
        <pre>
          <code>{node.value}</code>
        </pre>
      );
    case "thematicBreak":
      return <hr />;
    case "list": {
      const list = node as List;
      const children = (
        <For each={list.children}>{(item, itemIndex) => renderListItem(item, itemIndex)}</For>
      );
      return list.ordered ? <ol start={list.start ?? 1}>{children}</ol> : <ul>{children}</ul>;
    }
    case "table":
      return renderTable(node as Table);
    default:
      return null;
  }
}

function renderListItem(node: ListItem, index: () => number) {
  const isTask = typeof node.checked === "boolean";
  return (
    <li
      data-checked={isTask ? (node.checked ? "true" : "false") : undefined}
      data-item-index={index()}
    >
      {isTask ? (
        <>
          <input
            aria-label={node.checked ? "Completed task" : "Incomplete task"}
            checked={node.checked === true}
            disabled
            type="checkbox"
          />
          <div class="refmd-task-list-content">
            {renderBlockChildren(node.children as BlockContent[])}
          </div>
        </>
      ) : (
        renderBlockChildren(node.children as BlockContent[])
      )}
    </li>
  );
}

function renderTable(node: Table) {
  const [head, ...body] = node.children as TableRow[];

  return (
    <div class="refmd-markdown-table-wrapper">
      <table>
        <thead>
          {head && (
            <tr>
              <For each={head.children as TableCell[]}>
                {(cell, index) => (
                  <th style={{ "text-align": node.align?.[index()] ?? undefined }}>
                    {renderInlineChildren(cell.children)}
                  </th>
                )}
              </For>
            </tr>
          )}
        </thead>
        <tbody>
          <For each={body}>
            {(row) => (
              <tr>
                <For each={row.children as TableCell[]}>
                  {(cell, index) => (
                    <td style={{ "text-align": node.align?.[index()] ?? undefined }}>
                      {renderInlineChildren(cell.children)}
                    </td>
                  )}
                </For>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function renderBlockChildren(children: Array<RootContent | Content | DefinitionContent>) {
  return <For each={children}>{(child, index) => renderBlock(child, index)}</For>;
}

function collectHeadings(children: Root["children"], result: MarkdownViewHeading[] = []) {
  for (const child of children) {
    if (child.type === "heading") {
      const title = textFromInline(child.children);
      result.push({
        id: headingId(child, result.length),
        level: child.depth,
        title,
      });
    } else if (child.type === "blockquote") {
      collectHeadings(child.children as Root["children"], result);
    } else if (child.type === "list") {
      for (const item of child.children) {
        collectHeadings(item.children as Root["children"], result);
      }
    }
  }

  return result;
}

export function parseMarkdownView(markdown: string) {
  const { root, trailingNewlines } = parseMarkdownRoot(markdown);

  if (root.children.length === 0) {
    root.children = Array.from({ length: trailingNewlines + 1 }, () => ({
      type: "paragraph",
      children: [],
    }));
    return root;
  }

  root.children = [
    ...root.children,
    ...Array.from({ length: trailingNewlines }, () => ({ type: "paragraph", children: [] })),
  ] as Root["children"];

  return root;
}

export function markdownViewHeadings(root: Root): MarkdownViewHeading[] {
  return collectHeadings(root.children);
}

export function MarkdownView(props: { root: Root }) {
  return (
    <div class="refmd-markdown-view refmd-markdown-surface">
      {renderBlockChildren(props.root.children)}
    </div>
  );
}
