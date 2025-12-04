import { Link, useRouterState } from '@tanstack/react-router'
import type { LucideIcon } from 'lucide-react'
import { Command, Info, Sparkles, Users } from 'lucide-react'
import type { ReactNode } from 'react'

import { cn } from '@/shared/lib/utils'

type SettingsNavItem = {
  id: string
  label: string
  description: string
  icon: LucideIcon
  to: string
}

const normalizePath = (value: string) => value.replace(/\/+$/, '') || '/'

export const SETTINGS_NAV_ITEMS: SettingsNavItem[] = [
  {
    id: 'about',
    label: 'About RefMD',
    description: 'Platform overview and release highlights.',
    icon: Info,
    to: '/settings',
  },
  {
    id: 'shortcuts',
    label: 'Keyboard shortcuts',
    description: 'Customize editor key chords.',
    icon: Command,
    to: '/shortcuts',
  },
  {
    id: 'visibility',
    label: 'Public pages',
    description: 'Manage workspace visibility and sharing.',
    icon: Users,
    to: '/visibility',
  },
  {
    id: 'plugins',
    label: 'Plugins',
    description: 'Install and manage plugins.',
    icon: Sparkles,
    to: '/plugins',
  },
]

type SettingsShellProps = {
  header: { eyebrow?: string; title: string; description: string }
  children: ReactNode
}

export function SettingsShell({ header, children }: SettingsShellProps) {
  const pathname = useRouterState({ select: (s) => normalizePath(s.location.pathname) })

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto w-full max-w-[96rem] px-4 pb-16 pt-10 sm:px-6 md:px-10">
        <div className="flex w-full flex-col gap-6 lg:flex-row lg:gap-12">
          <nav className="w-full shrink-0 self-start lg:w-64" aria-label="Settings sections">
            <ul className="flex flex-col gap-2 text-sm lg:gap-1">
              {SETTINGS_NAV_ITEMS.map((item) => {
                const Icon = item.icon
                const target = normalizePath(item.to)
                const isActive = pathname === target || pathname.startsWith(`${target}/`)
                return (
                  <li key={item.id} className="w-full">
                    <Link
                      to={item.to}
                      aria-current={isActive ? 'page' : undefined}
                      className={cn(
                        'flex w-full items-center gap-2 rounded-2xl border border-border/40 bg-background/80 px-4 py-3 text-left text-sm transition-colors lg:rounded-xl lg:border-transparent lg:bg-transparent',
                        isActive ? 'bg-muted text-foreground lg:bg-muted' : 'hover:bg-muted/50',
                        'no-underline'
                      )}
                    >
                      <Icon className="h-4 w-4 text-primary" />
                      <div className="flex min-w-0 flex-col">
                        <span className="truncate font-medium">{item.label}</span>
                        <span className="truncate text-xs text-muted-foreground/80">{item.description}</span>
                      </div>
                    </Link>
                  </li>
                )
              })}
            </ul>
          </nav>

          <div className="flex-1 space-y-6">
            <div className="rounded-3xl border border-border/60 p-6 shadow-sm">
              <div className="space-y-3">
                <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
                  {header.eyebrow ? <span>{header.eyebrow}</span> : null}
                  <span>{header.title}</span>
                </div>
                <div className="space-y-2">
                  <h1 className="text-2xl font-semibold text-foreground">{header.title}</h1>
                  <p className="text-sm text-muted-foreground">{header.description}</p>
                </div>
              </div>
            </div>

            {children}
          </div>
        </div>
      </div>
    </div>
  )
}
