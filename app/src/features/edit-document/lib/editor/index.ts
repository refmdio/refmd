import { closeBrackets, closeBracketsKeymap, completionKeymap } from '@codemirror/autocomplete'
import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands'
import { markdown, markdownLanguage } from '@codemirror/lang-markdown'
import { bracketMatching, indentOnInput, foldGutter, foldKeymap } from '@codemirror/language'
import { languages } from '@codemirror/language-data'
import { searchKeymap, highlightSelectionMatches } from '@codemirror/search'
import { Extension, EditorState, Compartment } from '@codemirror/state'
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection, dropCursor, rectangularSelection, crosshairCursor, highlightSpecialChars } from '@codemirror/view'

import { refmdLightTheme, refmdDarkTheme } from './theme'
import { getVimPlaceholder } from './vim'
import { wikiLinkExtension } from './wiki-link'

export interface EditorConfig {
  isDarkMode: boolean
  readOnly: boolean
  vimMode: boolean
  isMobile: boolean
  lineWrapping?: boolean
}

export const themeCompartment = new Compartment()
export const readOnlyCompartment = new Compartment()
export const collabCompartment = new Compartment()

export function createBaseExtensions(config: EditorConfig): Extension[] {
  const theme = config.isDarkMode ? refmdDarkTheme : refmdLightTheme

  const extensions: Extension[] = [
    highlightSpecialChars(),
    history(),
    drawSelection(),
    dropCursor(),
    EditorState.allowMultipleSelections.of(true),
    indentOnInput(),
    bracketMatching(),
    closeBrackets(),
    rectangularSelection(),
    crosshairCursor(),
    highlightActiveLine(),
    highlightActiveLineGutter(),
    highlightSelectionMatches(),
    keymap.of([
      ...closeBracketsKeymap,
      ...defaultKeymap,
      ...searchKeymap,
      ...historyKeymap,
      ...foldKeymap,
      ...completionKeymap,
      indentWithTab,
    ]),
    markdown({
      base: markdownLanguage,
      codeLanguages: languages,
    }),
    wikiLinkExtension(),
    themeCompartment.of(theme),
    readOnlyCompartment.of(EditorState.readOnly.of(config.readOnly)),
    getVimPlaceholder(),
  ]

  if (!config.isMobile) {
    extensions.push(lineNumbers())
    extensions.push(foldGutter())
  }

  if (config.lineWrapping !== false) {
    extensions.push(EditorView.lineWrapping)
  }

  return extensions
}

export function createEditorExtensions(config: EditorConfig): Extension[] {
  return createBaseExtensions(config)
}

export function getThemeExtension(isDarkMode: boolean): Extension {
  return isDarkMode ? refmdDarkTheme : refmdLightTheme
}

export { refmdLightTheme, refmdDarkTheme } from './theme'
export { vimCompartment, enableVimMode, disableVimMode, toggleVimMode } from './vim'
export { wikiLinkExtension } from './wiki-link'
