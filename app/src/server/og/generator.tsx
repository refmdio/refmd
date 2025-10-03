import { Resvg } from '@resvg/resvg-js'
import satori from 'satori'

import type { OgImageVariant } from '@/shared/lib/og'

import { loadOgFonts } from './fonts'

const WIDTH = 1200
const HEIGHT = 630

export type OgImageOptions = {
  title: string
  subtitle?: string
  description?: string
  badge?: string
  meta?: string
  variant?: OgImageVariant
}

type VariantTheme = {
  badge: string
  accent: string
  background: string
  gradient: string
  subtitleColor: string
  descriptionColor: string
}

const VARIANT_THEME: Record<OgImageVariant, VariantTheme> = {
  default: {
    badge: 'RefMD',
    accent: '#8f86e8',
    background: '#14141b',
    gradient:
      'radial-gradient(at 15% 20%, rgba(143,134,232,0.35), transparent 58%), radial-gradient(at 80% 75%, rgba(95,179,179,0.22), transparent 60%)',
    subtitleColor: 'rgba(212,215,224,0.9)',
    descriptionColor: 'rgba(154,161,176,0.82)',
  },
  document: {
    badge: 'Document',
    accent: '#8f86e8',
    background: '#151622',
    gradient:
      'radial-gradient(at 18% 22%, rgba(143,134,232,0.38), transparent 55%), radial-gradient(at 82% 78%, rgba(119,112,224,0.25), transparent 60%)',
    subtitleColor: 'rgba(212,215,224,0.9)',
    descriptionColor: 'rgba(154,161,176,0.82)',
  },
  'public-document': {
    badge: 'Public Document',
    accent: '#5fb3b3',
    background: '#141b21',
    gradient:
      'radial-gradient(at 18% 24%, rgba(95,179,179,0.35), transparent 55%), radial-gradient(at 82% 76%, rgba(143,134,232,0.22), transparent 58%)',
    subtitleColor: 'rgba(209,223,231,0.9)',
    descriptionColor: 'rgba(167,196,205,0.82)',
  },
  'public-profile': {
    badge: 'Public Profile',
    accent: '#f28fad',
    background: '#1b1420',
    gradient:
      'radial-gradient(at 16% 22%, rgba(242,143,173,0.33), transparent 56%), radial-gradient(at 78% 80%, rgba(143,134,232,0.24), transparent 60%)',
    subtitleColor: 'rgba(240,213,226,0.9)',
    descriptionColor: 'rgba(208,169,188,0.82)',
  },
  'share-folder': {
    badge: 'Shared Folder',
    accent: '#4fd67c',
    background: '#122019',
    gradient:
      'radial-gradient(at 20% 24%, rgba(79,214,124,0.34), transparent 56%), radial-gradient(at 80% 78%, rgba(95,179,179,0.22), transparent 60%)',
    subtitleColor: 'rgba(201,239,217,0.9)',
    descriptionColor: 'rgba(172,219,191,0.82)',
  },
}

const clampText = (value: string | null | undefined, max = 140) => {
  if (!value) return ''
  const trimmed = value.trim().replace(/\s+/g, ' ')
  if (trimmed.length <= max) return trimmed
  return `${trimmed.slice(0, max - 3)}...`
}

const buildTemplate = (options: Required<Pick<OgImageOptions, 'title'>> & {
  subtitle: string
  description: string
  badge: string
  theme: VariantTheme
}) => {
  const { title, subtitle, description, badge, theme } = options
  return (
    <div
      style={{
        width: `${WIDTH}px`,
        height: `${HEIGHT}px`,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '72px',
        backgroundColor: theme.background,
        backgroundImage: theme.gradient,
        color: '#f4f5f7',
        fontFamily: 'Noto Sans JP',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div
          style={{
            padding: '12px 22px',
            borderRadius: '999px',
            backgroundColor: 'rgba(20,22,34,0.7)',
            border: `1px solid ${theme.accent}`,
            color: theme.accent,
            fontSize: '28px',
            fontWeight: 600,
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
          }}
        >
          {badge}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '18px',
              backgroundColor: theme.accent,
              color: theme.background,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 800,
              fontSize: '30px',
            }}
          >
            R
          </div>
          <div style={{ fontSize: '46px', fontWeight: 700, letterSpacing: '-0.02em', color: 'rgba(236,238,245,0.92)' }}>RefMD</div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', marginTop: '48px' }}>
        {subtitle ? (
          <div style={{ fontSize: '34px', color: theme.subtitleColor, fontWeight: 500 }}>{subtitle}</div>
        ) : null}
        <div
          style={{
            fontSize: '84px',
            fontWeight: 800,
            lineHeight: 1.05,
            letterSpacing: '-0.03em',
            color: 'rgba(236,238,245,0.96)',
            wordBreak: 'break-word',
          }}
        >
          {title}
        </div>
        {description ? (
          <div style={{ fontSize: '34px', lineHeight: 1.35, color: theme.descriptionColor }}>{description}</div>
        ) : null}
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div />
        <div style={{ fontSize: '24px', color: 'rgba(236,238,245,0.92)', letterSpacing: '0.01em' }}>refmd.io</div>
      </div>
    </div>
  )
}

export async function generateOgImage(input: OgImageOptions) {
  const fonts = await loadOgFonts()
  const variant = input.variant ?? 'default'
  const theme = VARIANT_THEME[variant]
  const title = clampText(input.title, 150) || 'RefMD'
  const subtitle = clampText(input.subtitle, 120)
  const description = clampText(input.description, 220)
  const badge = clampText(input.badge, 60) || theme.badge
  const template = buildTemplate({ title, subtitle, description, badge, theme })

  const svg = await satori(template, {
    width: WIDTH,
    height: HEIGHT,
    fonts,
  })

  const resvg = new Resvg(svg, {
    fitTo: { mode: 'original' },
    background: 'transparent',
  })

  const png = resvg.render().asPng()
  return Uint8Array.from(png)
}
