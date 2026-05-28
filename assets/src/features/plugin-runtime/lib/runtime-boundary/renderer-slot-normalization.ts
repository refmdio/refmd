import type { PluginRendererSlot } from "../renderer/host-renderer";

export function normalizeRendererSlots(
  value: readonly unknown[] | undefined,
): readonly PluginRendererSlot[] {
  if (!Array.isArray(value)) return [];

  return value.flatMap((entry): PluginRendererSlot[] => {
    if (!isRecord(entry) || typeof entry.type !== "string" || entry.type.trim() === "") {
      return [];
    }
    if (entry.kind === "inline") {
      return entry.type === "code" ? [{ kind: "inline", type: "code" }] : [];
    }
    if (entry.kind !== "block") return [];
    return [{ kind: "block", type: entry.type }];
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
