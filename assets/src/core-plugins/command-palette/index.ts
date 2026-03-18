import { render } from "solid-js/web";
import type { App } from "@/shared/lib/app-context";
import { setCommandPaletteOpen, CommandPaletteModal } from "./CommandPaletteModal";

let currentApp: App | null = null;
let disposeModal: (() => void) | null = null;

export function loadCommandPalette(app: App): void {
  currentApp = app;
  app.workspace.addCommand({
    id: "command-palette:open",
    name: "Open command palette",
    hotkeys: [{ modifiers: ["Mod"], key: "p" }],
    callback: () => setCommandPaletteOpen(true),
  });

  const container = document.createElement("div");
  document.body.appendChild(container);
  disposeModal = render(() => CommandPaletteModal(), container);
}

export function unloadCommandPalette(): void {
  if (!currentApp) return;
  currentApp.workspace.removeCommand("command-palette:open");
  setCommandPaletteOpen(false);
  disposeModal?.();
  disposeModal = null;
  currentApp = null;
}
