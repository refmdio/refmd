import type { Root } from "mdast";
import {
  MarkdownView,
  markdownViewHeadings,
  parseMarkdownView,
  type MarkdownViewHeading,
} from "@/shared/lib/markdown/markdown-view";

export type PublicMarkdownHeading = MarkdownViewHeading;

export function parsePublicMarkdown(markdown: string) {
  return parseMarkdownView(markdown);
}

export function publicMarkdownHeadings(root: Root): PublicMarkdownHeading[] {
  return markdownViewHeadings(root);
}

export function PublicMarkdownView(props: { root: Root }) {
  return <MarkdownView root={props.root} />;
}
