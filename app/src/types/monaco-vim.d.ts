declare module 'monaco-vim' {
  export interface VimMode {
    dispose(): void
  }
  export function initVimMode(editor: any, statusbar: HTMLElement): VimMode
}

