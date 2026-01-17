import { Extension, Compartment } from '@codemirror/state'
import { EditorView } from '@codemirror/view'
import { vim } from '@replit/codemirror-vim'

export const vimCompartment = new Compartment()

export interface VimModeState {
  enabled: boolean
  statusBarElement?: HTMLElement | null
}

export function createVimExtension(): Extension {
  return vim()
}

export function enableVimMode(view: EditorView): void {
  const vimExt = createVimExtension()
  view.dispatch({
    effects: vimCompartment.reconfigure(vimExt),
  })
}

export function disableVimMode(view: EditorView): void {
  view.dispatch({
    effects: vimCompartment.reconfigure([]),
  })
}

export function toggleVimMode(view: EditorView, enabled: boolean): void {
  if (enabled) {
    enableVimMode(view)
  } else {
    disableVimMode(view)
  }
}

export function getVimPlaceholder(): Extension {
  return vimCompartment.of([])
}

export { vim }
