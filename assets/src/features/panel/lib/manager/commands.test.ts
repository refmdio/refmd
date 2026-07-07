import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import type { Command, WorkspaceSurfaceOwner } from "@/shared/lib/workspace/app";
import { CommandsState } from "./commands";

const owner: WorkspaceSurfaceOwner = {
  kind: "built_in",
  workspaceId: "workspace-alpha",
  ownerId: "test-command",
  generation: 1,
};

describe("CommandsState", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects commands without workspace surface owners", () => {
    const commands = new CommandsState(() => null);

    expect(() =>
      commands.add({
        id: "missing-owner",
        name: "Missing owner",
      } as Command),
    ).toThrow("Command missing-owner is missing a workspace surface owner");
  });

  it("stores commands with workspace surface owners", () => {
    const commands = new CommandsState(() => null);

    commands.add({
      id: "owned-command",
      name: "Owned command",
      owner,
    });

    expect(commands.list()).toEqual([
      {
        id: "owned-command",
        name: "Owned command",
        owner,
      },
    ]);
  });

  it("removes commands by workspace surface owner predicate", () => {
    const commands = new CommandsState(() => null);

    commands.add({
      id: "owned-command",
      name: "Owned command",
      owner,
    });
    commands.add({
      id: "other-command",
      name: "Other command",
      owner: { ...owner, workspaceId: "workspace-beta" },
    });

    commands.removeByOwner((candidate) => candidate.workspaceId === "workspace-alpha");

    expect(commands.list().map((command) => command.id)).toEqual(["other-command"]);
  });

  it("uses checkCallback only as an availability check when a hotkey command has a callback", () => {
    const commands = new CommandsState(() => null);
    const callback = vi.fn();
    const checkCallback = vi.fn(() => true);

    commands.add({
      id: "plugin-command",
      name: "Plugin command",
      owner,
      hotkeys: [{ modifiers: ["Mod"], key: "k" }],
      callback,
      checkCallback,
    });

    commands.init();
    window.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "k",
        ctrlKey: true,
        bubbles: true,
        cancelable: true,
      }),
    );
    commands.reset();

    expect(checkCallback).toHaveBeenCalledTimes(1);
    expect(checkCallback).toHaveBeenCalledWith(true);
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("falls back to checkCallback execution for hotkey commands without a callback", () => {
    const commands = new CommandsState(() => null);
    const checkCallback = vi.fn(() => true);

    commands.add({
      id: "legacy-command",
      name: "Legacy command",
      owner,
      hotkeys: [{ modifiers: ["Mod"], key: "l" }],
      checkCallback,
    });

    commands.init();
    window.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "l",
        ctrlKey: true,
        bubbles: true,
        cancelable: true,
      }),
    );
    commands.reset();

    expect(checkCallback).toHaveBeenCalledTimes(2);
    expect(checkCallback).toHaveBeenNthCalledWith(1, true);
    expect(checkCallback).toHaveBeenNthCalledWith(2, false);
  });
});
