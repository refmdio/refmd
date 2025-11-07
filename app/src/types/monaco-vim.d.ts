declare module 'monaco-vim' {
  export interface VimStatusBar {
    setKeyBuffer(buffer: string): void
    setMode(mode: { mode: string }): void
    toggleVisibility(isVisible: boolean): void
    closeInput(): void
    clear(): void
  }

  export interface VimAdapter {
    dispose(): void
    on(event: string, handler: (...args: any[]) => void): void
    attach(): void
    setStatusBar(statusBar: VimStatusBar): void
  }

  export interface VimMode {
    dispose(): void
  }

  export interface CodeMirrorShim {
    Vim?: {
      defineMotion: (name: string, fn: (...args: any[]) => any) => void
    }
  }

  export const VimMode: CodeMirrorShim

  export function initVimMode(editor: any, statusbar: HTMLElement): VimMode
}
