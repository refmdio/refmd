export type OgImageVariant = 'default' | 'document' | 'public-document' | 'public-profile' | 'share-folder'

const OG_VARIANTS: OgImageVariant[] = ['default', 'document', 'public-document', 'public-profile', 'share-folder']
const OG_VARIANT_SET = new Set<string>(OG_VARIANTS)

export function normalizeOgImageVariant(value?: string): OgImageVariant {
  if (!value) return 'default'
  const normalized = value.toLowerCase()
  return OG_VARIANT_SET.has(normalized) ? (normalized as OgImageVariant) : 'default'
}

export function isOgImageVariant(value: string): value is OgImageVariant {
  return OG_VARIANT_SET.has(value)
}

export function buildOgImagePath(variant: OgImageVariant): string {
  return `/og/${variant}.png`
}
