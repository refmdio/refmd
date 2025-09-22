export function generateHeadingId(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[`~!@#$%^&*()_+={}\[\]|\\:;"'<>?,.\/]/g, '')
    .replace(/\s+/g, '-')
}
