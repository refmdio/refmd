import type { AppDocuments } from "@/shared/lib/document/manager";
import { APP_INSTANCE_KEY, type App, type AppWorkspace } from "@/shared/lib/workspace/app";

type GlobalAppState = typeof globalThis & {
  [APP_INSTANCE_KEY]?: App | null;
};

export function initApp(
  workspace: AppWorkspace,
  documentServices: {
    documents: AppDocuments;
  },
): App {
  const app: App = {
    workspace,
    ...documentServices,
    isDarkMode: () => document.documentElement.classList.contains("dark"),
  };

  (globalThis as GlobalAppState)[APP_INSTANCE_KEY] = app;
  return app;
}
