/**
 * PDF Export
 *
 * Converts Markdown to PDF using pandoc-wasm + browser print
 * This mirrors the backend implementation which used:
 *   Pandoc (markdown → HTML) + wkhtmltopdf (HTML → PDF)
 *
 * All processing happens client-side for E2EE compliance.
 * Uses browser's native print functionality for accurate rendering.
 */

import { exportWithPandoc } from './pandoc'

export interface PdfExportOptions {
  /** Document ID for resolving attachments */
  documentId?: string
  /** Function to resolve and decrypt attachment paths to data URIs */
  resolveAttachment?: (path: string) => Promise<string | null>
}

/**
 * CSS matching backend wkhtmltopdf output
 */
const PDF_STYLES = `
  @page {
    size: A4;
    margin: 20mm;
  }

  @media print {
    body {
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
  }

  body {
    font-family: 'Noto Sans CJK JP', 'Noto Sans CJK SC', 'Noto Sans CJK TC', 'Noto Sans CJK KR',
                 'Noto Sans JP', 'Noto Sans', 'Noto Serif CJK JP', 'Noto Serif CJK SC',
                 'Noto Serif CJK TC', 'Noto Serif CJK KR', 'Source Han Sans JP', 'Source Han Sans SC',
                 'Source Han Sans TC', 'Source Han Sans KR', 'Hiragino Kaku Gothic ProN', 'Yu Gothic',
                 'PingFang SC', 'Microsoft YaHei', 'Microsoft JhengHei', 'Malgun Gothic',
                 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 12pt;
    line-height: 1.5;
    color: #000;
    margin: 0;
    padding: 0;
  }

  code, pre {
    font-family: 'Noto Sans Mono CJK JP', 'Noto Sans Mono', 'Source Code Pro', 'Roboto Mono',
                 'Menlo', 'Consolas', monospace;
  }

  h1 { font-size: 2em; margin: 0.67em 0; }
  h2 { font-size: 1.5em; margin: 0.83em 0; }
  h3 { font-size: 1.17em; margin: 1em 0; }
  h4 { font-size: 1em; margin: 1.33em 0; }
  h5 { font-size: 0.83em; margin: 1.67em 0; }
  h6 { font-size: 0.67em; margin: 2.33em 0; }

  p { margin: 1em 0; }
  ul, ol { margin: 1em 0; padding-left: 2em; }
  li { margin: 0.25em 0; }

  pre {
    background: #f8f8f8;
    padding: 0.5em;
    overflow-x: auto;
    border: 1px solid #ccc;
    white-space: pre-wrap;
    word-wrap: break-word;
  }

  code { font-size: 0.9em; }
  pre code { background: none; border: none; padding: 0; }

  blockquote {
    margin: 1em 2em;
    padding-left: 1em;
    border-left: 2px solid #ccc;
    color: #555;
  }

  table { border-collapse: collapse; margin: 1em 0; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 0.5em; text-align: left; }
  th { background: #f0f0f0; font-weight: bold; }

  img { max-width: 100%; height: auto; }
  figure { margin: 1em 0; }
  figcaption { font-size: 0.9em; color: #666; text-align: center; margin-top: 0.5em; }

  a { color: #0066cc; text-decoration: underline; }
  hr { border: none; border-top: 1px solid #ccc; margin: 1em 0; }

  input[type="checkbox"] { margin-right: 0.5em; }
`

/**
 * Export to PDF using browser print dialog
 *
 * Flow: Markdown → HTML (pandoc) → Print dialog (browser)
 * Returns a dummy blob since actual PDF is created via print dialog
 */
export async function exportToPdf(
  markdown: string,
  title: string,
  options?: PdfExportOptions
): Promise<Blob> {
  // 1. Convert markdown to HTML using pandoc-wasm (non-standalone for body content only)
  const htmlBlob = await exportWithPandoc(markdown, 'html5', 'text/html', {
    standalone: false,
  })

  // Get HTML string (body content only)
  let bodyContent = await htmlBlob.text()

  // 2. Resolve and embed images as data URIs if resolver is provided
  if (options?.resolveAttachment) {
    bodyContent = await embedImages(bodyContent, options.resolveAttachment)
  }

  // 3. Open print window with styled content
  await openPrintWindow(bodyContent, title)

  // Return empty blob (actual PDF is created via print dialog)
  return new Blob([], { type: 'application/pdf' })
}

/**
 * Open a new window with print-ready content
 */
async function openPrintWindow(bodyContent: string, title: string): Promise<void> {
  const printWindow = window.open('', '_blank')
  if (!printWindow) {
    throw new Error('Failed to open print window. Please allow popups for this site.')
  }

  const htmlDocument = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(title)}</title>
  <style>${PDF_STYLES}</style>
</head>
<body>
  ${bodyContent}
</body>
</html>
`

  printWindow.document.write(htmlDocument)
  printWindow.document.close()

  // Wait for images to load
  await new Promise<void>((resolve) => {
    const images = printWindow.document.querySelectorAll('img')
    if (images.length === 0) {
      resolve()
      return
    }

    let loaded = 0
    const checkDone = () => {
      loaded++
      if (loaded >= images.length) {
        resolve()
      }
    }

    images.forEach((img) => {
      if (img.complete) {
        checkDone()
      } else {
        img.onload = checkDone
        img.onerror = checkDone
      }
    })

    // Timeout fallback
    setTimeout(resolve, 3000)
  })

  // Small delay for rendering
  await new Promise((resolve) => setTimeout(resolve, 100))

  // Trigger print dialog
  printWindow.print()
}

/**
 * Escape HTML special characters
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/**
 * Embed images as base64 data URIs
 */
async function embedImages(
  html: string,
  resolveAttachment: (path: string) => Promise<string | null>
): Promise<string> {
  // Find all img tags with src attributes
  const imgRegex = /<img\s+[^>]*src="([^"]+)"[^>]*>/gi
  const matches: { fullMatch: string; src: string }[] = []

  let match
  while ((match = imgRegex.exec(html)) !== null) {
    matches.push({ fullMatch: match[0], src: match[1] })
  }

  if (matches.length === 0) {
    return html
  }

  // Resolve all images in parallel
  const resolved = await Promise.all(
    matches.map(async ({ fullMatch, src }) => {
      // Skip external URLs and data URIs
      if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('data:')) {
        return { fullMatch, src, dataUri: null }
      }

      try {
        const dataUri = await resolveAttachment(src)
        return { fullMatch, src, dataUri }
      } catch (error) {
        console.warn('[PDF Export] Failed to resolve attachment:', src, error)
        return { fullMatch, src, dataUri: null }
      }
    })
  )

  // Replace src attributes with data URIs
  let result = html
  for (const { fullMatch, src, dataUri } of resolved) {
    if (dataUri) {
      const newTag = fullMatch.replace(`src="${src}"`, `src="${dataUri}"`)
      result = result.replace(fullMatch, newTag)
    }
  }

  return result
}

