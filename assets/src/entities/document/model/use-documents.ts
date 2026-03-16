import { type Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { documentsApi } from "@/shared/api";
import { authState, deviceState } from "@/shared/lib/auth-state";
import { buildDocumentTree } from "../lib/build-tree";

export function useDocuments(workspaceId: Accessor<string | null>) {
  const query = createQuery(() => ({
    queryKey: ["documents", workspaceId()],
    queryFn: () => documentsApi.list(workspaceId()!),
    enabled: !!authState() && !!deviceState()?.deviceSigningPrivate && !!workspaceId(),
  }));

  const flatDocuments = () => query.data?.documents ?? [];

  const documentTree = () => buildDocumentTree(flatDocuments());

  return { documentTree, flatDocuments, query };
}
