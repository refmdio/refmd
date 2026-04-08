import type { Command } from "@/shared/lib/workspace/app";
import { matchesHotkey } from "./hotkeys";

type EditorContext = { editor: unknown; doc: unknown } | null;
type EditorContextResolver = () => EditorContext;

export class CommandsState {
  private readonly commands = new Map<string, Command>();
  private hotkeyHandler: ((event: KeyboardEvent) => void) | null = null;
  private readonly resolveEditorContext: EditorContextResolver;

  constructor(resolveEditorContext: EditorContextResolver) {
    this.resolveEditorContext = resolveEditorContext;
  }

  init(): void {
    if (this.hotkeyHandler) return;
    this.hotkeyHandler = this.handleHotkey.bind(this);
    if (typeof window !== "undefined") {
      window.addEventListener("keydown", this.hotkeyHandler, true);
    }
  }

  reset(): void {
    if (this.hotkeyHandler && typeof window !== "undefined") {
      window.removeEventListener("keydown", this.hotkeyHandler, true);
      this.hotkeyHandler = null;
    }
    this.commands.clear();
  }

  add(command: Command): Command {
    this.commands.set(command.id, command);
    return command;
  }

  remove(commandId: string): void {
    this.commands.delete(commandId);
  }

  list(): Command[] {
    return [...this.commands.values()];
  }

  private handleHotkey(event: KeyboardEvent): void {
    if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) {
      return;
    }
    for (const command of this.commands.values()) {
      if (!command.hotkeys) continue;
      for (const hotkey of command.hotkeys) {
        if (!matchesHotkey(event, hotkey)) continue;
        event.preventDefault();
        event.stopPropagation();
        this.execute(command);
        return;
      }
    }
  }

  private execute(command: Command): void {
    if (command.editorCheckCallback) {
      const context = this.resolveEditorContext();
      if (!context) return;
      const canRun = command.editorCheckCallback(true, context.editor, context.doc);
      if (canRun) command.editorCheckCallback(false, context.editor, context.doc);
      return;
    }
    if (command.editorCallback) {
      const context = this.resolveEditorContext();
      if (context) {
        command.editorCallback(context.editor, context.doc);
      }
      return;
    }
    if (command.checkCallback) {
      const canRun = command.checkCallback(true);
      if (canRun) command.checkCallback(false);
      return;
    }
    command.callback?.();
  }
}
