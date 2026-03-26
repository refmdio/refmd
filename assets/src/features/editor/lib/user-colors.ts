import type { Awareness } from "y-protocols/awareness";

const CURSOR_COLORS = [
  "#e06c75",
  "#61afef",
  "#98c379",
  "#d19a66",
  "#c678dd",
  "#56b6c2",
  "#e5c07b",
  "#be5046",
  "#528bff",
  "#7ec699",
] as const;

function hashUserId(userId: string): number {
  let hash = 0;
  for (let i = 0; i < userId.length; i++) {
    hash = ((hash << 5) - hash + userId.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

function getUsedColors(awareness: Awareness, excludeUserId: string): Set<string> {
  const used = new Set<string>();
  awareness.getStates().forEach((state) => {
    const user = state.user as { userId?: string; color?: string } | undefined;
    if (user?.color && user.userId !== excludeUserId) {
      used.add(user.color);
    }
  });
  return used;
}

export function assignUserColor(userId: string, awareness?: Awareness): string {
  const preferredIndex = hashUserId(userId) % CURSOR_COLORS.length;

  if (!awareness) {
    return CURSOR_COLORS[preferredIndex];
  }

  const used = getUsedColors(awareness, userId);

  if (!used.has(CURSOR_COLORS[preferredIndex])) {
    return CURSOR_COLORS[preferredIndex];
  }

  for (let offset = 1; offset < CURSOR_COLORS.length; offset++) {
    const candidate = CURSOR_COLORS[(preferredIndex + offset) % CURSOR_COLORS.length];
    if (!used.has(candidate)) {
      return candidate;
    }
  }

  return CURSOR_COLORS[preferredIndex];
}
