import {
  DOWNLOAD_FORMAT_METADATA,
  type DocumentDownloadFormat,
  type DocumentDownloadFormatMetadata,
} from '@/entities/document'

export type DownloadOption = {
  format: DocumentDownloadFormat
  label: string
  description: string
}

export type DownloadOptionGroup = {
  title: string
  description?: string
  items: DownloadOption[]
}

const PRIMARY_FORMATS: DocumentDownloadFormat[] = ['archive', 'markdown', 'html', 'pdf', 'docx']

export const PRIMARY_DOWNLOAD_OPTIONS: DownloadOption[] = PRIMARY_FORMATS.map((format) => {
  const meta = DOWNLOAD_FORMAT_METADATA[format]
  return { format, label: meta.label, description: meta.description }
})

const OTHER_GROUP_TITLES: string[] = [
  'Web & Slides',
  'TeX & Academic',
  'Office & Rich Text',
  'E-books',
  'Wiki & Markup',
  'Data & Interchange',
  'Manuals',
]

const GROUP_DESCRIPTIONS: Record<string, string> = {
  'Web & Slides': 'HTML presentations and web-ready documents.',
  'TeX & Academic': 'TeX-based outputs for academic workflows.',
  'Office & Rich Text': 'Office document formats and rich text.',
  'E-books': 'Digital book formats supported by e-readers.',
  'Wiki & Markup': 'Markup languages and wiki syntaxes.',
  'Data & Interchange': 'Structured data formats and AST exports.',
  Manuals: 'Formats suited for manuals and reference pages.',
}

const METADATA_ENTRIES = Object.entries(DOWNLOAD_FORMAT_METADATA) as Array<
  [DocumentDownloadFormat, DocumentDownloadFormatMetadata]
>

export const OTHER_DOWNLOAD_FORMAT_GROUPS: DownloadOptionGroup[] = (() => {
  const groups = OTHER_GROUP_TITLES.map((title) => {
    const items = METADATA_ENTRIES.filter(
      ([, meta]) => meta.category === 'other' && meta.group === title,
    ).map(([format, meta]) => ({ format, label: meta.label, description: meta.description }))
    return {
      title,
      description: GROUP_DESCRIPTIONS[title],
      items,
    }
  }).filter((group) => group.items.length > 0)

  const remaining = METADATA_ENTRIES.filter(
    ([, meta]) => meta.category === 'other' && (!meta.group || !OTHER_GROUP_TITLES.includes(meta.group)),
  ).map(([format, meta]) => ({ format, label: meta.label, description: meta.description }))

  if (remaining.length > 0) {
    groups.push({
      title: 'Other formats',
      description: 'Additional writers supported by Pandoc.',
      items: remaining,
    })
  }

  return groups
})()
