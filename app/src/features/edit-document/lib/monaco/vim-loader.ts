import type * as monacoNs from 'monaco-editor'

type MonacoVimModule = typeof import('monaco-vim')

let cachedModulePromise: Promise<MonacoVimModule> | null = null
let vimPatched = false

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value))

type CmAdapter = {
  editor?: monacoNs.editor.IStandaloneCodeEditor
  clipPos: (pos: { line: number; ch: number }) => { line: number; ch: number }
}

type VimState = {
  lastMotion?: unknown
  lastHPos?: number
  lastHSPos?: number
}

type MotionArgs = {
  forward: boolean
  repeat: number
}

type MotionHandler = (
  cm: CmAdapter,
  head: { line: number; ch: number },
  motionArgs: MotionArgs,
  vim: VimState,
) => { line: number; ch: number }

type MotionsShape = Record<string, MotionHandler>

const getViewModel = (editor: monacoNs.editor.IStandaloneCodeEditor) => (editor as any)?._getViewModel?.()

const toModelPosition = (pos: { line: number; ch: number }) => ({
  lineNumber: pos.line + 1,
  column: pos.ch + 1,
})

const patchDisplayLineMotion = (module: MonacoVimModule) => {
  if (vimPatched) return

  const codeMirror = module.VimMode
  const vimApi = codeMirror?.Vim
  if (!vimApi?.defineMotion) return

  const defineMotion = vimApi.defineMotion.bind(vimApi)

  defineMotion('moveByDisplayLines', function moveByDisplayLines(this: MotionsShape, cm, head, motionArgs, vim) {
    const editor = cm.editor
    const viewModel = editor ? getViewModel(editor) : null
    const fallback = () => (typeof this.moveByLines === 'function' ? this.moveByLines(cm, head, motionArgs, vim) : head)

    if (!editor || !viewModel) {
      return fallback()
    }

    const converter = viewModel.coordinatesConverter
    const modelStart = toModelPosition(head)
    const viewStart = converter.convertModelPositionToViewPosition(modelStart)
    const viewLineCount = typeof viewModel.getLineCount === 'function' ? viewModel.getLineCount() : 0
    if (!viewLineCount) {
      return fallback()
    }

    const repeat = Math.max(1, motionArgs.repeat || 1)
    const direction = motionArgs.forward ? 1 : -1

    const startZeroColumn = Math.max(0, viewStart.column - 1)
    let goalColumn = typeof vim.lastHSPos === 'number' ? vim.lastHSPos : startZeroColumn
    switch (vim.lastMotion) {
      case this.moveByDisplayLines:
      case this.moveByScroll:
      case this.moveByLines:
      case this.moveToColumn:
      case this.moveToEol:
        break
      default:
        goalColumn = startZeroColumn
        vim.lastHSPos = goalColumn
    }

    const rawTargetLine = viewStart.lineNumber + direction * repeat
    const targetLine = clamp(rawTargetLine, 1, viewLineCount)
    const maxColumn = Math.max(1, viewModel.getLineMaxColumn(targetLine) ?? 1)
    const maxZeroColumn = Math.max(0, maxColumn - 1)
    const resolvedColumn = clamp(goalColumn, 0, maxZeroColumn)

    const targetViewPos = { lineNumber: targetLine, column: resolvedColumn + 1 }
    const targetModelPos = converter.convertViewPositionToModelPosition(targetViewPos)
    const candidate = cm.clipPos({
      line: targetModelPos.lineNumber - 1,
      ch: targetModelPos.column - 1,
    })

    vim.lastHSPos = goalColumn
    vim.lastHPos = candidate.ch
    return candidate
  })

  vimPatched = true
}

export async function loadMonacoVim() {
  if (!cachedModulePromise) {
    cachedModulePromise = import('monaco-vim').then((module) => {
      patchDisplayLineMotion(module)
      return module
    })
  }
  return cachedModulePromise
}
