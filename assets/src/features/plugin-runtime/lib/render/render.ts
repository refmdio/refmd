import { getOwner, type JSX, type Owner } from "solid-js";
import { QueryClientProvider } from "@tanstack/solid-query";
import { render } from "solid-js/web";
import { queryClient } from "@/shared/lib/query/client";

type RenderWithOwner = (
  component: () => JSX.Element,
  container: HTMLElement,
  init?: unknown,
  options?: { owner?: Owner },
) => () => void;

let pluginRenderOwner: Owner | null = null;
let defaultPluginRenderOwner: Owner | null = null;

export function setDefaultPluginRenderOwner(owner: Owner | null): () => void {
  const previousOwner = defaultPluginRenderOwner;
  defaultPluginRenderOwner = owner;
  return () => {
    if (defaultPluginRenderOwner === owner) {
      defaultPluginRenderOwner = previousOwner;
    }
  };
}

export function withPluginRenderOwner<T>(owner: Owner | null, fn: () => T): T {
  const previousOwner = pluginRenderOwner;
  pluginRenderOwner = owner;
  try {
    return fn();
  } finally {
    pluginRenderOwner = previousOwner;
  }
}

export function renderTrustedBuiltinContent(
  component: () => JSX.Element,
  container: HTMLElement,
): () => void {
  const owner = pluginRenderOwner ?? defaultPluginRenderOwner ?? getOwner();
  return (render as RenderWithOwner)(
    () =>
      QueryClientProvider({
        client: queryClient,
        get children() {
          return component();
        },
      }),
    container,
    undefined,
    owner ? { owner } : undefined,
  );
}
