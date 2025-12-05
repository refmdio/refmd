import type * as monacoNs from 'monaco-editor'

export const REFMD_LIGHT_THEME = 'refmd-light'
export const REFMD_DARK_THEME = 'refmd-dark'

const stripHash = (hex: string) => hex.replace('#', '')

const pad = (n: number) => n.toString(16).padStart(2, '0')

const hexToRgb = (hex: string) => {
  const h = stripHash(hex)
  const bigint = parseInt(h, 16)
  const r = (bigint >> 16) & 255
  const g = (bigint >> 8) & 255
  const b = bigint & 255
  return { r, g, b }
}

const hexWithAlpha = (hex: string, alpha: number) => {
  const a = Math.min(Math.max(alpha, 0), 1)
  const { r, g, b } = hexToRgb(hex)
  const alphaHex = pad(Math.round(a * 255))
  return `#${pad(r)}${pad(g)}${pad(b)}${alphaHex}`
}

const mixHexWithWhite = (hex: string, weight: number) => {
  const { r, g, b } = hexToRgb(hex)
  const w = Math.min(Math.max(weight, 0), 1)
  const mix = (c: number) => Math.round(c + (255 - c) * w)
  return `#${pad(mix(r))}${pad(mix(g))}${pad(mix(b))}`
}

type Palette = {
  primary: string
  background: string
  foreground: string
  mutedForeground: string
  codeBlockBg: string
  codeBlockFg: string
}

const LIGHT_PALETTE: Palette = {
  primary: '#6e63d6',
  background: '#ffffff',
  foreground: '#252a33',
  mutedForeground: '#596272',
  codeBlockBg: '#fafafa',
  codeBlockFg: '#24292e',
}

const DARK_PALETTE: Palette = {
  primary: '#8f86e8',
  background: '#1e1e1e',
  foreground: '#e4e7eb',
  mutedForeground: '#9aa1b0',
  codeBlockBg: '#242424',
  codeBlockFg: '#f3f4f6',
}

type ThemeDefinition = {
  name: string
  data: monacoNs.editor.IStandaloneThemeData
}

const buildTheme = (name: string, palette: Palette, isDark: boolean): ThemeDefinition => {
  const softPrimary = mixHexWithWhite(palette.primary, isDark ? 0.3 : 0.55)
  const linkColor = mixHexWithWhite(palette.primary, isDark ? 0.2 : 0.35)
  const keywordColor = stripHash(palette.primary)
  const defaultFg = stripHash(palette.foreground)

  return {
    name,
    data: {
      base: isDark ? 'vs-dark' : 'vs',
      inherit: false,
      rules: [
        { token: '', foreground: defaultFg },
        { token: 'keyword', foreground: keywordColor, fontStyle: 'bold' },
        { token: 'keyword.table.header', foreground: keywordColor, fontStyle: 'bold' },
        { token: 'keyword.table.left', foreground: keywordColor, fontStyle: 'bold' },
        { token: 'keyword.table.middle', foreground: keywordColor, fontStyle: 'bold' },
        { token: 'keyword.table.right', foreground: keywordColor, fontStyle: 'bold' },
        { token: 'strong', foreground: keywordColor, fontStyle: 'bold' },
        { token: 'emphasis', foreground: keywordColor, fontStyle: 'italic' },
        { token: 'string', foreground: stripHash(softPrimary) },
        { token: 'string.link', foreground: stripHash(linkColor), fontStyle: 'underline' },
        { token: 'string.target', foreground: stripHash(linkColor) },
        { token: 'variable', foreground: stripHash(mixHexWithWhite(palette.foreground, isDark ? 0.08 : 0.12)) },
        { token: 'delimiter', foreground: defaultFg },
        { token: 'delimiter.parenthesis', foreground: defaultFg },
        { token: 'delimiter.bracket', foreground: defaultFg },
        { token: 'delimiter.curly', foreground: defaultFg },
        { token: 'operator', foreground: defaultFg },
        {
          token: 'variable.source',
          foreground: stripHash(palette.codeBlockFg),
          background: stripHash(palette.codeBlockBg),
        },
      ],
      colors: {
        'editor.background': palette.background,
        'editor.foreground': palette.foreground,
        'editorLineNumber.foreground': hexWithAlpha(palette.foreground, 0.45),
        'editorLineNumber.activeForeground': palette.primary,
        'editor.selectionBackground': hexWithAlpha(palette.primary, isDark ? 0.22 : 0.16),
        'editor.selectionHighlightBackground': hexWithAlpha(palette.primary, isDark ? 0.16 : 0.12),
        'editor.wordHighlightBackground': hexWithAlpha(palette.primary, isDark ? 0.16 : 0.12),
        'editor.findMatchHighlightBackground': hexWithAlpha(palette.primary, isDark ? 0.2 : 0.14),
        'editorBracketMatch.background': hexWithAlpha(palette.primary, isDark ? 0.16 : 0.1),
        'editorBracketMatch.border': hexWithAlpha(palette.primary, isDark ? 0.55 : 0.42),
        'editorBracketHighlight.foreground1': palette.foreground,
        'editorBracketHighlight.foreground2': palette.foreground,
        'editorBracketHighlight.foreground3': palette.foreground,
        'editorBracketHighlight.foreground4': palette.foreground,
        'editorBracketHighlight.foreground5': palette.foreground,
        'editorBracketHighlight.foreground6': palette.foreground,
        'editorBracketHighlight.unexpectedBracket.foreground': palette.foreground,
        'editorCursor.foreground': palette.primary,
        'editorIndentGuide.background': hexWithAlpha(palette.foreground, 0.12),
        'editorIndentGuide.activeBackground': hexWithAlpha(palette.primary, isDark ? 0.3 : 0.24),
        'editor.lineHighlightBackground': hexWithAlpha(palette.primary, isDark ? 0.08 : 0.06),
        'editor.selectionHighlightBorder': hexWithAlpha(palette.foreground, 0.16),
      },
    },
  }
}

const themeDefinitions: ThemeDefinition[] = [
  buildTheme(REFMD_LIGHT_THEME, LIGHT_PALETTE, false),
  buildTheme(REFMD_DARK_THEME, DARK_PALETTE, true),
]

type MonacoNamespace = typeof import('monaco-editor')

export function ensureRefmdThemes(monaco: MonacoNamespace) {
  themeDefinitions.forEach(({ name, data }) => {
    monaco.editor.defineTheme(name, data)
  })
}
