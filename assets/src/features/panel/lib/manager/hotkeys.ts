import type { Hotkey } from "@/shared/lib/workspace/app";

const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.userAgent);

export function matchesHotkey(event: KeyboardEvent, hotkey: Hotkey): boolean {
  const modifiers = new Set(hotkey.modifiers);
  const needCtrl = modifiers.has("Ctrl") || (!isMac && modifiers.has("Mod"));
  const needMeta = modifiers.has("Meta") || (isMac && modifiers.has("Mod"));
  const needShift = modifiers.has("Shift");
  const needAlt = modifiers.has("Alt");

  if (event.ctrlKey !== needCtrl) return false;
  if (event.metaKey !== needMeta) return false;
  if (event.shiftKey !== needShift) return false;
  if (event.altKey !== needAlt) return false;

  return event.key.toLowerCase() === hotkey.key.toLowerCase();
}
