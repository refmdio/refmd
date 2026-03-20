import { type Accessor } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { documentsApi } from "@/shared/api";
import { authState, cryptoWorkerReady } from "@/shared/lib/auth-state";

export function useDocuments(workspaceId: Accessor<string | null>) {
  const query = createQuery(() => ({
    queryKey: ["documents", workspaceId()],
    queryFn: () => documentsApi.list(workspaceId()!),
    enabled: !!authState() && cryptoWorkerReady() && !!workspaceId(),
  }));

  const flatDocuments = () => query.data?.documents ?? [];

  return { flatDocuments, query };
}
