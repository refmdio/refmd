declare module 'wasm-pandoc' {
  export interface PandocResult {
    out: string | Blob
    mediaFiles: Map<string, Map<string, Blob>>
  }

  export interface PandocFile {
    filename: string
    contents: string | Blob
  }

  export function pandoc(
    args: string,
    input: string | Blob,
    files?: PandocFile[]
  ): Promise<PandocResult>
}
