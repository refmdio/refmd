export function normalizeMarkdown(value: string): string {
  return value.replace(/\r\n?/g, "\n").replace(/\n+$/, "");
}
