/**
 * Export Feature Module
 *
 * E2EE-compliant client-side document export.
 * All conversion happens after decryption, ensuring server never sees plaintext.
 *
 * Architecture:
 * - Most formats: pandoc-wasm (dynamically imported on first use)
 * - PDF: pdfmake (pandoc cannot generate PDF without LaTeX)
 * - Archive: jszip
 */

// Formats
export {
  type ExportFormat,
  type PandocOutputFormat,
  type ExportFormatCategory,
  type ExportFormatMetadata,
  EXPORT_FORMATS,
  getFormatMetadata,
  getExtension,
  getMimeType,
  getPandocFormat,
  sanitizeFilename,
} from './lib/formats'

// Pandoc conversion (primary converter for most formats)
export {
  convertWithPandoc,
  exportWithPandoc,
  isPandocLoaded,
  preloadPandoc,
} from './lib/pandoc'

// Special converters
export { exportToPdf, type PdfExportOptions } from './lib/pdf'
export {
  createArchive,
  createDocumentArchive,
  createWorkspaceArchive,
  type ArchiveFile,
} from './lib/archive'

// Hooks
export {
  useExport,
  exportDocumentFile,
  type UseExportOptions,
  type UseExportResult,
  type ExportState,
} from './hooks/useExport'
