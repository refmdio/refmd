import { createSignal, createMemo, For, Show } from "solid-js";
import { workspaceManager } from "@/features/panel";
import { getActiveEditor } from "@/features/editor";
import { getApp } from "@/shared/lib/workspace/app";
import type { Command } from "@/shared/lib/workspace/app";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@/shared/ui/command";

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
  const { documents } = getApp();
  const [query, setQuery] = createSignal("");

  const getActiveCommandContext = () => {
    const editor = getActiveEditor();
    const doc = documents.getActiveDocument();
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
      if (!cmd.checkCallback(true)) return;
      if (cmd.callback) {
        cmd.callback();
      } else {
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

  const close = () => setCommandPaletteOpen(false);

  return (
    <CommandDialog
      open={commandPaletteOpen()}
      onOpenChange={(open: boolean) => setCommandPaletteOpen(open)}
      title="Command Palette"
      description="Search for a command to run."
    >
      <CommandInput placeholder="Type a command..." value={query()} onValueChange={setQuery} />
      <CommandList>
        <CommandEmpty>No matching commands</CommandEmpty>
        <CommandGroup value="commands">
          <For each={filteredCommands()}>
            {(cmd) => (
              <CommandItem value={cmd.id} keywords={[cmd.name]} onSelect={() => runCommand(cmd)}>
                <span>{cmd.name}</span>
                <Show when={cmd.hotkeys && cmd.hotkeys.length > 0}>
                  <CommandShortcut>{formatHotkey(cmd.hotkeys![0])}</CommandShortcut>
                </Show>
              </CommandItem>
            )}
          </For>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
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
