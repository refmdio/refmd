/**
 * User Color Assignment
 *
 * Deterministic color assignment based on user ID for cursor and presence rendering.
 * Uses a palette of 10 distinct, accessible colors.
 */

const CURSOR_COLORS = [
  '#e06c75', // red
  '#61afef', // blue
  '#98c379', // green
  '#d19a66', // orange
  '#c678dd', // purple
  '#56b6c2', // cyan
  '#e5c07b', // yellow
  '#be5046', // dark red
  '#528bff', // bright blue
  '#7ec699', // mint
] as const

/**
 * Assign a deterministic color to a user based on their ID.
 * Uses a simple hash to index into the color palette.
 */
export function assignUserColor(userId: string): string {
  let hash = 0
  for (let i = 0; i < userId.length; i++) {
    hash = ((hash << 5) - hash + userId.charCodeAt(i)) | 0
  }
  return CURSOR_COLORS[Math.abs(hash) % CURSOR_COLORS.length]
}
