import { EditorView } from '@codemirror/view'
import { Extension } from '@codemirror/state'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags } from '@lezer/highlight'

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

const hexToRgb = (hex: string) => {
  const h = hex.replace('#', '')
  const bigint = parseInt(h, 16)
  const r = (bigint >> 16) & 255
  const g = (bigint >> 8) & 255
  const b = bigint & 255
  return { r, g, b }
}

const hexWithAlpha = (hex: string, alpha: number) => {
  const { r, g, b } = hexToRgb(hex)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

const mixHexWithWhite = (hex: string, weight: number) => {
  const { r, g, b } = hexToRgb(hex)
  const w = Math.min(Math.max(weight, 0), 1)
  const mix = (c: number) => Math.round(c + (255 - c) * w)
  const pad = (n: number) => n.toString(16).padStart(2, '0')
  return `#${pad(mix(r))}${pad(mix(g))}${pad(mix(b))}`
}

function buildTheme(palette: Palette, isDark: boolean): Extension {
  const softPrimary = mixHexWithWhite(palette.primary, isDark ? 0.3 : 0.55)
  const linkColor = mixHexWithWhite(palette.primary, isDark ? 0.2 : 0.35)

  const theme = EditorView.theme(
    {
      '&': {
        color: palette.foreground,
        backgroundColor: palette.background,
        height: '100%',
      },
      '.cm-content': {
        caretColor: palette.primary,
        fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace',
        fontSize: '14px',
        lineHeight: '1.6',
      },
      '.cm-cursor, .cm-dropCursor': {
        borderLeftColor: palette.primary,
        borderLeftWidth: '2px',
      },
      '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.22 : 0.16),
      },
      '.cm-panels': {
        backgroundColor: palette.background,
        color: palette.foreground,
      },
      '.cm-panels.cm-panels-top': {
        borderBottom: `1px solid ${hexWithAlpha(palette.foreground, 0.1)}`,
      },
      '.cm-panels.cm-panels-bottom': {
        borderTop: `1px solid ${hexWithAlpha(palette.foreground, 0.1)}`,
      },
      '.cm-searchMatch': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.2 : 0.14),
        outline: `1px solid ${hexWithAlpha(palette.primary, 0.3)}`,
      },
      '.cm-searchMatch.cm-searchMatch-selected': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.35 : 0.25),
      },
      '.cm-activeLine': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.08 : 0.06),
      },
      '.cm-selectionMatch': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.16 : 0.12),
      },
      '&.cm-focused .cm-matchingBracket, &.cm-focused .cm-nonmatchingBracket': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.16 : 0.1),
        outline: `1px solid ${hexWithAlpha(palette.primary, isDark ? 0.55 : 0.42)}`,
      },
      '.cm-gutters': {
        backgroundColor: palette.background,
        color: hexWithAlpha(palette.foreground, 0.45),
        border: 'none',
      },
      '.cm-activeLineGutter': {
        backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.08 : 0.06),
        color: palette.primary,
      },
      '.cm-foldPlaceholder': {
        backgroundColor: 'transparent',
        border: 'none',
        color: palette.mutedForeground,
      },
      '.cm-tooltip': {
        border: `1px solid ${hexWithAlpha(palette.foreground, 0.15)}`,
        backgroundColor: palette.background,
        color: palette.foreground,
        borderRadius: '6px',
        boxShadow: isDark
          ? '0 4px 12px rgba(0, 0, 0, 0.4)'
          : '0 4px 12px rgba(0, 0, 0, 0.1)',
      },
      '.cm-tooltip .cm-tooltip-arrow:before': {
        borderTopColor: 'transparent',
        borderBottomColor: 'transparent',
      },
      '.cm-tooltip .cm-tooltip-arrow:after': {
        borderTopColor: palette.background,
        borderBottomColor: palette.background,
      },
      '.cm-tooltip-autocomplete': {
        '& > ul > li[aria-selected]': {
          backgroundColor: hexWithAlpha(palette.primary, isDark ? 0.2 : 0.12),
          color: palette.foreground,
        },
      },
      '.cm-completionLabel': {
        color: palette.foreground,
      },
      '.cm-completionDetail': {
        color: palette.mutedForeground,
      },
      '.cm-completionMatchedText': {
        color: palette.primary,
        fontWeight: '600',
        textDecoration: 'none',
      },
      '.cm-line': {
        padding: '0 4px',
      },
      '.cm-scroller': {
        overflow: 'auto',
      },
    },
    { dark: isDark }
  )

  const highlightStyle = HighlightStyle.define([
    { tag: tags.heading, fontWeight: 'bold', color: palette.primary },
    { tag: tags.heading1, fontSize: '1.5em' },
    { tag: tags.heading2, fontSize: '1.3em' },
    { tag: tags.heading3, fontSize: '1.15em' },
    { tag: tags.strong, fontWeight: 'bold', color: palette.primary },
    { tag: tags.emphasis, fontStyle: 'italic', color: palette.primary },
    { tag: tags.strikethrough, textDecoration: 'line-through' },
    { tag: tags.link, color: linkColor, textDecoration: 'underline' },
    { tag: tags.url, color: linkColor },
    { tag: tags.monospace, fontFamily: 'monospace', color: palette.codeBlockFg, backgroundColor: palette.codeBlockBg },
    { tag: tags.quote, color: palette.mutedForeground, fontStyle: 'italic' },
    { tag: tags.list, color: palette.foreground },
    { tag: tags.meta, color: palette.mutedForeground },
    { tag: tags.processingInstruction, color: softPrimary },
    { tag: tags.comment, color: palette.mutedForeground },
    { tag: tags.keyword, color: palette.primary, fontWeight: 'bold' },
    { tag: tags.string, color: softPrimary },
    { tag: tags.number, color: softPrimary },
    { tag: tags.operator, color: palette.foreground },
    { tag: tags.punctuation, color: palette.mutedForeground },
    { tag: tags.bracket, color: palette.foreground },
    { tag: tags.variableName, color: palette.foreground },
    { tag: tags.propertyName, color: palette.primary },
    { tag: tags.function(tags.variableName), color: palette.primary },
    { tag: tags.typeName, color: softPrimary },
    { tag: tags.className, color: softPrimary },
    { tag: tags.labelName, color: palette.primary },
    { tag: tags.attributeName, color: palette.primary },
    { tag: tags.attributeValue, color: softPrimary },
    { tag: tags.tagName, color: palette.primary },
    { tag: tags.angleBracket, color: palette.mutedForeground },
    { tag: tags.contentSeparator, color: palette.mutedForeground },
  ])

  return [theme, syntaxHighlighting(highlightStyle)]
}

export const refmdLightTheme: Extension = buildTheme(LIGHT_PALETTE, false)
export const refmdDarkTheme: Extension = buildTheme(DARK_PALETTE, true)

export { LIGHT_PALETTE, DARK_PALETTE }
export type { Palette }
