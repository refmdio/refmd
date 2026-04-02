import { createSignal, createEffect, createMemo, For, Show } from "solid-js";
import { Portal } from "solid-js/web";
import { workspaceManager } from "@/features/panel";
import { getActiveEditor } from "@/features/editor";
import { getApp } from "@/shared/lib/app-context";
import type { Command } from "@/shared/lib/app-context";

const [commandPaletteOpen, setCommandPaletteOpen] = createSignal(false);

export { setCommandPaletteOpen };

function fuzzyMatch(query: string, text: string): number {
  if (!query) return 1;
  const lowerText = text.toLowerCase();
  const lowerQuery = query.toLowerCase();
  let textIdx = 0;
  let score = 0;
  let consecutive = 0;
  for (let i = 0; i < lowerQuery.length; i++) {
    const ch = lowerQuery[i];
    if (ch === " ") continue;
    const found = lowerText.indexOf(ch, textIdx);
    if (found === -1) return 0;
    if (found === textIdx) {
      consecutive++;
      score += consecutive;
    } else {
      consecutive = 1;
      score += 1;
    }
    if (found === 0 || lowerText[found - 1] === " ") score += 2;
    textIdx = found + 1;
  }
  return score;
}

export function CommandPaletteModal() {
  return (
    <Show when={commandPaletteOpen()}>
      <CommandPaletteInner />
    </Show>
  );
}

function CommandPaletteInner() {
  const { documentQueries } = getApp();
  const [query, setQuery] = createSignal("");
  const [selectedIndex, setSelectedIndex] = createSignal(0);
  const [inputRef, setInputRef] = createSignal<HTMLInputElement>();

  const getActiveCommandContext = () => {
    const editor = getActiveEditor();
    const doc = documentQueries.getActiveDocument();
    return editor && doc ? { editor, doc } : null;
  };

  const isCommandAvailable = (cmd: Command) => {
    if (cmd.id === "command-palette:open") return false;

    const context = getActiveCommandContext();
    if (cmd.editorCheckCallback) {
      return context ? cmd.editorCheckCallback(true, context.editor, context.doc) !== false : false;
    }
    if (cmd.editorCallback) {
      return context !== null;
    }
    if (cmd.checkCallback) return cmd.checkCallback(true) !== false;
    return true;
  };

  const runCommand = (cmd: Command) => {
    close();

    const context = getActiveCommandContext();
    if (cmd.editorCheckCallback) {
      if (context && cmd.editorCheckCallback(true, context.editor, context.doc)) {
        cmd.editorCheckCallback(false, context.editor, context.doc);
      }
      return;
    }
    if (cmd.editorCallback) {
      if (context) {
        cmd.editorCallback(context.editor, context.doc);
      }
      return;
    }
    if (cmd.checkCallback) {
      if (cmd.checkCallback(true)) {
        cmd.checkCallback(false);
      }
      return;
    }
    cmd.callback?.();
  };

  const filteredCommands = createMemo(() => {
    const q = query();
    const commands = workspaceManager.listCommands().filter(isCommandAvailable);
    if (!q) return commands;

    return commands
      .map((cmd) => ({ cmd, score: fuzzyMatch(q, cmd.name) }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .map((x) => x.cmd);
  });

  createEffect(() => {
    filteredCommands();
    setSelectedIndex(0);
  });

  const close = () => setCommandPaletteOpen(false);

  const execute = (idx: number) => {
    const cmds = filteredCommands();
    const cmd = cmds[idx];
    if (!cmd) return;
    runCommand(cmd);
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    const cmds = filteredCommands();
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, cmds.length - 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        break;
      case "Enter":
        e.preventDefault();
        execute(selectedIndex());
        break;
      case "Escape":
        e.preventDefault();
        close();
        break;
    }
  };

  const handleBackdropClick = (e: MouseEvent) => {
    if ((e.target as HTMLElement).dataset.backdrop) {
      close();
    }
  };

  createEffect(() => {
    inputRef()?.focus();
  });

  return (
    <Portal>
      <div
        data-backdrop="true"
        class="fixed inset-0 z-50 bg-black/50 flex items-start justify-center pt-[15vh]"
        onClick={handleBackdropClick}
      >
        <div class="bg-popover border border-border rounded-lg shadow-lg w-full max-w-md overflow-hidden">
          <div class="p-2 border-b border-border">
            <input
              ref={setInputRef}
              type="text"
              class="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              placeholder="Type a command..."
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              onKeyDown={handleKeyDown}
            />
          </div>
          <div class="max-h-64 overflow-y-auto">
            <Show
              when={filteredCommands().length > 0}
              fallback={
                <div class="p-3 text-sm text-muted-foreground text-center">
                  No matching commands
                </div>
              }
            >
              <For each={filteredCommands()}>
                {(cmd, idx) => (
                  <button
                    class={`w-full text-left px-3 py-2 text-sm flex items-center justify-between hover:bg-accent ${
                      idx() === selectedIndex() ? "bg-accent" : ""
                    }`}
                    onMouseEnter={() => setSelectedIndex(idx())}
                    onClick={() => execute(idx())}
                  >
                    <span>{cmd.name}</span>
                    <Show when={cmd.hotkeys && cmd.hotkeys.length > 0}>
                      <kbd class="text-xs text-muted-foreground ml-2">
                        {formatHotkey(cmd.hotkeys![0])}
                      </kbd>
                    </Show>
                  </button>
                )}
              </For>
            </Show>
          </div>
        </div>
      </div>
    </Portal>
  );
}

function formatHotkey(hotkey: { modifiers: string[]; key: string }): string {
  const isMac = /Mac/.test(navigator.userAgent);
  const parts = hotkey.modifiers.map((m) => {
    if (m === "Mod") return isMac ? "\u2318" : "Ctrl";
    if (m === "Shift") return isMac ? "\u21E7" : "Shift";
    if (m === "Alt") return isMac ? "\u2325" : "Alt";
    if (m === "Ctrl") return "Ctrl";
    if (m === "Meta") return "\u2318";
    return m;
  });
  parts.push(hotkey.key.toUpperCase());
  return parts.join(isMac ? "" : "+");
}
