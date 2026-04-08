import type { JSX } from "solid-js";
import { QueryClientProvider } from "@tanstack/solid-query";
import { render } from "solid-js/web";
import { queryClient } from "@/shared/lib/query/client";

export function renderPluginContent(
  component: () => JSX.Element,
  container: HTMLElement,
): () => void {
  return render(
    () =>
      QueryClientProvider({
        client: queryClient,
        get children() {
          return component();
        },
      }),
    container,
  );
}
