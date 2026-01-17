/**
 * Export Format Definitions
 *
 * Defines supported export formats for E2EE-compliant client-side export.
 * - PDF: pdfmake (LaTeX not available in browser)
 * - Other formats: pandoc-wasm
 */

// Pandoc output format names
export type PandocOutputFormat =
  | 'markdown'
  | 'html'
  | 'html5'
  | 'latex'
  | 'beamer'
  | 'context'
  | 'man'
  | 'mediawiki'
  | 'dokuwiki'
  | 'textile'
  | 'org'
  | 'texinfo'
  | 'opml'
  | 'docbook'
  | 'opendocument'
  | 'odt'
  | 'docx'
  | 'rtf'
  | 'epub'
  | 'epub3'
  | 'fb2'
  | 'asciidoc'
  | 'icml'
  | 'slidy'
  | 'slideous'
  | 'dzslides'
  | 'revealjs'
  | 's5'
  | 'json'
  | 'plain'
  | 'commonmark'
  | 'commonmark_x'
  | 'markdown_strict'
  | 'markdown_phpextra'
  | 'gfm'
  | 'rst'
  | 'native'
  | 'haddock'

// All export formats (includes archive and pdf which are handled specially)
export type ExportFormat =
  | 'archive'
  | 'pdf'
  | PandocOutputFormat

export type ExportFormatCategory = 'primary' | 'other'

export interface ExportFormatMetadata {
  label: string
  description: string
  extension: string
  mimeType: string
  category: ExportFormatCategory
  group?: string
  /** If true, use html2pdf.js (pandoc → HTML → PDF) */
  useHtml2Pdf?: boolean
  /** If true, this is a ZIP archive (special handling) */
  isArchive?: boolean
  /** Pandoc format name (if different from key) */
  pandocFormat?: PandocOutputFormat
}

export const EXPORT_FORMATS: Record<ExportFormat, ExportFormatMetadata> = {
  // Primary formats
  archive: {
    label: 'ZIP Archive (.zip)',
    description: 'Markdown with all attachments bundled',
    extension: 'zip',
    mimeType: 'application/zip',
    category: 'primary',
    isArchive: true,
  },
  markdown: {
    label: 'Markdown (.md)',
    description: 'Plain markdown document',
    extension: 'md',
    mimeType: 'text/markdown; charset=utf-8',
    category: 'primary',
    pandocFormat: 'markdown',
  },
  html: {
    label: 'HTML (.html)',
    description: 'Self-contained HTML page',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'primary',
    pandocFormat: 'html5',
  },
  pdf: {
    label: 'PDF (.pdf)',
    description: 'Portable Document Format',
    extension: 'pdf',
    mimeType: 'application/pdf',
    category: 'primary',
    useHtml2Pdf: true,
  },
  docx: {
    label: 'Word (.docx)',
    description: 'Microsoft Word document',
    extension: 'docx',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    category: 'primary',
    pandocFormat: 'docx',
  },

  // Web & Slides
  html5: {
    label: 'HTML5 (.html)',
    description: 'HTML5 output; self-contained page',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'other',
    group: 'Web & Slides',
    pandocFormat: 'html5',
  },
  slidy: {
    label: 'Slidy (.html)',
    description: 'Slidy HTML presentation',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'other',
    group: 'Web & Slides',
    pandocFormat: 'slidy',
  },
  slideous: {
    label: 'Slideous (.html)',
    description: 'Slideous HTML presentation',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'other',
    group: 'Web & Slides',
    pandocFormat: 'slideous',
  },
  dzslides: {
    label: 'DZSlides (.html)',
    description: 'DZSlides HTML presentation',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'other',
    group: 'Web & Slides',
    pandocFormat: 'dzslides',
  },
  revealjs: {
    label: 'reveal.js (.html)',
    description: 'reveal.js HTML presentation',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'other',
    group: 'Web & Slides',
    pandocFormat: 'revealjs',
  },
  s5: {
    label: 'S5 (.html)',
    description: 'S5 HTML presentation',
    extension: 'html',
    mimeType: 'text/html; charset=utf-8',
    category: 'other',
    group: 'Web & Slides',
    pandocFormat: 's5',
  },

  // TeX & Academic
  latex: {
    label: 'LaTeX (.tex)',
    description: 'LaTeX document source',
    extension: 'tex',
    mimeType: 'application/x-tex; charset=utf-8',
    category: 'other',
    group: 'TeX & Academic',
    pandocFormat: 'latex',
  },
  beamer: {
    label: 'Beamer slides (.tex)',
    description: 'LaTeX Beamer slide deck',
    extension: 'tex',
    mimeType: 'application/x-tex; charset=utf-8',
    category: 'other',
    group: 'TeX & Academic',
    pandocFormat: 'beamer',
  },
  context: {
    label: 'ConTeXt (.tex)',
    description: 'ConTeXt document source',
    extension: 'tex',
    mimeType: 'application/x-tex; charset=utf-8',
    category: 'other',
    group: 'TeX & Academic',
    pandocFormat: 'context',
  },

  // Office & Rich Text
  odt: {
    label: 'ODT (.odt)',
    description: 'OpenDocument Text document',
    extension: 'odt',
    mimeType: 'application/vnd.oasis.opendocument.text',
    category: 'other',
    group: 'Office & Rich Text',
    pandocFormat: 'odt',
  },
  opendocument: {
    label: 'OpenDocument Flat XML (.fodt)',
    description: 'Flat OpenDocument Text document',
    extension: 'fodt',
    mimeType: 'application/vnd.oasis.opendocument.text',
    category: 'other',
    group: 'Office & Rich Text',
    pandocFormat: 'opendocument',
  },
  rtf: {
    label: 'RTF (.rtf)',
    description: 'Rich Text Format document',
    extension: 'rtf',
    mimeType: 'application/rtf',
    category: 'other',
    group: 'Office & Rich Text',
    pandocFormat: 'rtf',
  },
  icml: {
    label: 'ICML (.icml)',
    description: 'Adobe InCopy ICML document',
    extension: 'icml',
    mimeType: 'application/xml',
    category: 'other',
    group: 'Office & Rich Text',
    pandocFormat: 'icml',
  },

  // E-books
  epub: {
    label: 'EPUB 2 (.epub)',
    description: 'EPUB eBook (v2)',
    extension: 'epub',
    mimeType: 'application/epub+zip',
    category: 'other',
    group: 'E-books',
    pandocFormat: 'epub',
  },
  epub3: {
    label: 'EPUB 3 (.epub)',
    description: 'EPUB eBook (v3)',
    extension: 'epub',
    mimeType: 'application/epub+zip',
    category: 'other',
    group: 'E-books',
    pandocFormat: 'epub3',
  },
  fb2: {
    label: 'FictionBook (.fb2)',
    description: 'FictionBook eBook',
    extension: 'fb2',
    mimeType: 'application/xml',
    category: 'other',
    group: 'E-books',
    pandocFormat: 'fb2',
  },

  // Wiki & Markup
  mediawiki: {
    label: 'MediaWiki (.mediawiki)',
    description: 'MediaWiki markup',
    extension: 'mediawiki',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'mediawiki',
  },
  dokuwiki: {
    label: 'DokuWiki (.txt)',
    description: 'DokuWiki markup',
    extension: 'txt',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'dokuwiki',
  },
  textile: {
    label: 'Textile (.textile)',
    description: 'Textile markup',
    extension: 'textile',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'textile',
  },
  org: {
    label: 'Org-mode (.org)',
    description: 'Emacs Org-mode document',
    extension: 'org',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'org',
  },
  texinfo: {
    label: 'Texinfo (.texi)',
    description: 'GNU Texinfo document',
    extension: 'texi',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'texinfo',
  },
  asciidoc: {
    label: 'AsciiDoc (.adoc)',
    description: 'AsciiDoc markup',
    extension: 'adoc',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'asciidoc',
  },
  rst: {
    label: 'reStructuredText (.rst)',
    description: 'reStructuredText document',
    extension: 'rst',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'rst',
  },
  plain: {
    label: 'Plain text (.txt)',
    description: 'Plain UTF-8 text output',
    extension: 'txt',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'plain',
  },
  commonmark: {
    label: 'CommonMark (.md)',
    description: 'CommonMark markdown',
    extension: 'md',
    mimeType: 'text/markdown; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'commonmark',
  },
  commonmark_x: {
    label: 'CommonMark+Extensions (.md)',
    description: 'CommonMark with extensions',
    extension: 'md',
    mimeType: 'text/markdown; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'commonmark_x',
  },
  markdown_strict: {
    label: 'Markdown (strict) (.md)',
    description: 'Original markdown syntax',
    extension: 'md',
    mimeType: 'text/markdown; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'markdown_strict',
  },
  markdown_phpextra: {
    label: 'Markdown (PHP Extra) (.md)',
    description: 'Markdown PHP Extra dialect',
    extension: 'md',
    mimeType: 'text/markdown; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'markdown_phpextra',
  },
  gfm: {
    label: 'GitHub Markdown (.md)',
    description: 'GitHub-flavoured markdown',
    extension: 'md',
    mimeType: 'text/markdown; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'gfm',
  },
  haddock: {
    label: 'Haddock (.txt)',
    description: 'Haddock markup (Haskell docs)',
    extension: 'txt',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Wiki & Markup',
    pandocFormat: 'haddock',
  },

  // Data & Interchange
  opml: {
    label: 'OPML (.opml)',
    description: 'Outline Processor Markup Language document',
    extension: 'opml',
    mimeType: 'application/xml',
    category: 'other',
    group: 'Data & Interchange',
    pandocFormat: 'opml',
  },
  docbook: {
    label: 'DocBook XML (.xml)',
    description: 'DocBook XML document',
    extension: 'xml',
    mimeType: 'application/xml',
    category: 'other',
    group: 'Data & Interchange',
    pandocFormat: 'docbook',
  },
  json: {
    label: 'Pandoc JSON (.json)',
    description: 'Pandoc JSON abstract syntax tree',
    extension: 'json',
    mimeType: 'application/json; charset=utf-8',
    category: 'other',
    group: 'Data & Interchange',
    pandocFormat: 'json',
  },
  native: {
    label: 'Pandoc native (.hs)',
    description: 'Pandoc native Haskell AST',
    extension: 'hs',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Data & Interchange',
    pandocFormat: 'native',
  },

  // Manuals
  man: {
    label: 'Man page (.man)',
    description: 'Groff man page source',
    extension: 'man',
    mimeType: 'text/plain; charset=utf-8',
    category: 'other',
    group: 'Manuals',
    pandocFormat: 'man',
  },
}

export function getFormatMetadata(format: ExportFormat): ExportFormatMetadata {
  return EXPORT_FORMATS[format]
}

export function getExtension(format: ExportFormat): string {
  return EXPORT_FORMATS[format].extension
}

export function getMimeType(format: ExportFormat): string {
  return EXPORT_FORMATS[format].mimeType
}

export function getPandocFormat(format: ExportFormat): PandocOutputFormat | null {
  const meta = EXPORT_FORMATS[format]
  if (meta.useHtml2Pdf || meta.isArchive) {
    return null
  }
  return meta.pandocFormat ?? (format as PandocOutputFormat)
}

export function sanitizeFilename(input: string): string {
  const invalid = new Set(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'])
  let base = (input ?? '').trim()
  if (!base) base = 'document'

  let sanitized = ''
  for (const ch of base) {
    sanitized += invalid.has(ch) ? '-' : ch
  }
  sanitized = sanitized.replace(/ /g, '_')
  if (sanitized.length > 100) sanitized = sanitized.slice(0, 100)
  if (!sanitized) sanitized = 'document'

  return sanitized
}
