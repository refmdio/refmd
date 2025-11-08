import type * as monacoNs from 'monaco-editor'

export const REFMD_LIGHT_THEME = 'refmd-light'
export const REFMD_DARK_THEME = 'refmd-dark'

const BRAND_LIGHT = '#6e63d6'
const BRAND_DARK = '#8f86e8'
const CODE_BLOCK_BG = '#242424'
const CODE_BLOCK_FG = '#f5f5f5'

const stripHash = (hex: string) => hex.replace('#', '')

type ThemeDefinition = {
  name: string
  data: monacoNs.editor.IStandaloneThemeData
}

const themeDefinitions: ThemeDefinition[] = [
  {
    name: REFMD_LIGHT_THEME,
    data: {
      base: 'vs',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: stripHash(BRAND_LIGHT), fontStyle: 'bold' },
        { token: 'keyword.table.header', foreground: stripHash(BRAND_LIGHT), fontStyle: 'bold' },
        { token: 'keyword.table.left', foreground: stripHash(BRAND_LIGHT), fontStyle: 'bold' },
        { token: 'keyword.table.middle', foreground: stripHash(BRAND_LIGHT), fontStyle: 'bold' },
        { token: 'keyword.table.right', foreground: stripHash(BRAND_LIGHT), fontStyle: 'bold' },
        { token: 'strong', foreground: stripHash(BRAND_LIGHT), fontStyle: 'bold' },
        { token: 'emphasis', foreground: stripHash(BRAND_LIGHT), fontStyle: 'italic' },
        { token: 'string.link', foreground: '4f63ff', fontStyle: 'underline' },
        { token: 'string.target', foreground: '4f63ff' },
        { token: 'variable', foreground: 'd97706' },
        {
          token: 'variable.source',
          foreground: stripHash(CODE_BLOCK_FG),
          background: stripHash(CODE_BLOCK_BG),
        },
      ],
      colors: {
        'editor.selectionBackground': `${BRAND_LIGHT}2e`,
        'editor.selectionHighlightBackground': `${BRAND_LIGHT}18`,
        'editor.wordHighlightBackground': `${BRAND_LIGHT}18`,
        'editor.findMatchHighlightBackground': `${BRAND_LIGHT}26`,
        'editorBracketMatch.background': `${BRAND_LIGHT}15`,
        'editorBracketMatch.border': `${BRAND_LIGHT}60`,
        'editorCursor.foreground': '#463ac7',
        'editorLineNumber.activeForeground': BRAND_LIGHT,
      },
    },
  },
  {
    name: REFMD_DARK_THEME,
    data: {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: stripHash(BRAND_DARK), fontStyle: 'bold' },
        { token: 'keyword.table.header', foreground: stripHash(BRAND_DARK), fontStyle: 'bold' },
        { token: 'keyword.table.left', foreground: stripHash(BRAND_DARK), fontStyle: 'bold' },
        { token: 'keyword.table.middle', foreground: stripHash(BRAND_DARK), fontStyle: 'bold' },
        { token: 'keyword.table.right', foreground: stripHash(BRAND_DARK), fontStyle: 'bold' },
        { token: 'strong', foreground: stripHash(BRAND_DARK), fontStyle: 'bold' },
        { token: 'emphasis', foreground: stripHash(BRAND_DARK), fontStyle: 'italic' },
        { token: 'string.link', foreground: 'b5c7ff', fontStyle: 'underline' },
        { token: 'string.target', foreground: 'b5c7ff' },
        { token: 'variable', foreground: 'f7c778' },
        {
          token: 'variable.source',
          foreground: stripHash(CODE_BLOCK_FG),
          background: stripHash(CODE_BLOCK_BG),
        },
      ],
      colors: {
        'editor.selectionBackground': `${BRAND_DARK}40`,
        'editor.selectionHighlightBackground': `${BRAND_DARK}25`,
        'editor.wordHighlightBackground': `${BRAND_DARK}25`,
        'editor.findMatchHighlightBackground': `${BRAND_DARK}30`,
        'editorBracketMatch.background': `${BRAND_DARK}26`,
        'editorBracketMatch.border': `${BRAND_DARK}70`,
        'editorCursor.foreground': '#d9d7ff',
        'editorLineNumber.activeForeground': BRAND_DARK,
      },
    },
  },
]

type MonacoNamespace = typeof import('monaco-editor')
type MonacoWithThemeFlag = MonacoNamespace & { __refmdThemesReady?: boolean }

export function ensureRefmdThemes(monaco: MonacoNamespace) {
  const anyMonaco = monaco as MonacoWithThemeFlag
  if (anyMonaco.__refmdThemesReady) return
  themeDefinitions.forEach(({ name, data }) => {
    monaco.editor.defineTheme(name, data)
  })
  anyMonaco.__refmdThemesReady = true
}
