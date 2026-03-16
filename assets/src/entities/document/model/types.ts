import type { components } from "@/shared/api";

export type DocumentResponse = components["schemas"]["DocumentResponse"];

export interface DocumentTreeNode {
  document: DocumentResponse;
  children: DocumentTreeNode[];
  depth: number;
}
