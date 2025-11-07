import type * as monacoNs from 'monaco-editor'
import type { CodeMirrorShim, RegisterController } from 'monaco-vim'

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

type PatchedRegisterController = RegisterController & { __clipboardHooked?: boolean }
type ResetFn = ((...args: unknown[]) => void) & { __clipboardWrapped?: boolean }

const maybeCopyToSystemClipboard = (operator?: string, text?: string) => {
  if (operator !== 'yank') return
  if (!text) return
  if (typeof navigator === 'undefined') return
  const clipboard = navigator.clipboard
  if (!clipboard?.writeText) return
  void clipboard.writeText(text).catch(() => {})
}

const patchRegisterClipboardSync = (vimApi: CodeMirrorShim['Vim']) => {
  if (!vimApi?.getRegisterController) return
  const controller = vimApi.getRegisterController() as PatchedRegisterController | undefined
  if (!controller || controller.__clipboardHooked) return
  const originalPushText = controller.pushText.bind(controller)
  controller.pushText = function patchedPushText(registerName, operator, text, linewise, blockwise) {
    maybeCopyToSystemClipboard(operator, text)
    return originalPushText(registerName, operator, text, linewise, blockwise)
  }
  controller.__clipboardHooked = true
}

const patchResetForClipboard = (vimApi: CodeMirrorShim['Vim']) => {
  if (!vimApi) return
  const api = vimApi as NonNullable<CodeMirrorShim['Vim']>
  const reset = api.resetVimGlobalState_ as ResetFn | undefined
  if (!reset || reset.__clipboardWrapped) return
  const wrapped: ResetFn = function wrappedReset(this: unknown, ...args: unknown[]) {
    reset.apply(this, args)
    patchRegisterClipboardSync(api)
  }
  wrapped.__clipboardWrapped = true
  api.resetVimGlobalState_ = wrapped as NonNullable<CodeMirrorShim['Vim']>['resetVimGlobalState_']
}

const setupClipboardSync = (vimApi: CodeMirrorShim['Vim']) => {
  if (!vimApi) return
  patchRegisterClipboardSync(vimApi)
  patchResetForClipboard(vimApi)
}

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

  setupClipboardSync(vimApi)
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
