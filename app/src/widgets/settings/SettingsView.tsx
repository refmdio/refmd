import { Command, EqualNot } from 'lucide-react'
import { useMemo, useState } from 'react'

import { cn } from '@/shared/lib/utils'

import { ShortcutSettingsCard } from '@/features/settings/shortcut-settings/ui/ShortcutSettingsCard'

const SETTINGS_TABS = [
  {
    id: 'shortcuts',
    label: 'Keyboard shortcuts',
    icon: Command,
    title: 'Keyboard shortcuts',
    description:
      'Customize the key chords used across the editor and workspace navigation. Changes apply per-user and sync across devices.',
  },
  {
    id: 'appearance',
    label: 'Appearance',
    icon: EqualNot,
    disabled: true,
    title: 'Appearance',
    description: 'Personalize editor fonts, theme accents, and more (coming soon).',
  },
]

export default function SettingsView() {
  const defaultTab = useMemo(() => SETTINGS_TABS[0]?.id ?? 'shortcuts', [])
  const [activeTab, setActiveTab] = useState(defaultTab)
  const activeMeta = SETTINGS_TABS.find((tab) => tab.id === activeTab) ?? SETTINGS_TABS[0]

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto w-full max-w-6xl px-4 pb-16 pt-10 sm:px-6 md:px-8">
        <div className="flex w-full flex-col gap-6 lg:flex-row lg:gap-8">
          <nav className="w-full shrink-0 self-start lg:w-56" aria-label="Settings sections">
            <ul className="flex flex-col gap-2 text-sm lg:gap-1">
              {SETTINGS_TABS.map((tab) => {
                const Icon = tab.icon
                const isActive = activeTab === tab.id
                return (
                  <li key={tab.id} className="w-full">
                    <button
                      type="button"
                      disabled={tab.disabled}
                      onClick={() => setActiveTab(tab.id)}
                      aria-current={isActive ? 'page' : undefined}
                      className={cn(
                        'flex w-full items-center gap-2 rounded-2xl border border-border/40 bg-background/80 px-4 py-3 text-left text-sm transition-colors lg:rounded-xl lg:border-transparent lg:bg-transparent',
                        isActive ? 'bg-muted text-foreground lg:bg-muted' : 'hover:bg-muted/50',
                        tab.disabled && 'opacity-50'
                      )}
                    >
                      <Icon className="h-4 w-4 text-primary" />
                      <span className="truncate">{tab.label}</span>
                      {tab.disabled && (
                        <span className="ml-auto rounded-full bg-muted px-2 py-0.5 text-[11px] uppercase tracking-wide">
                          Soon
                        </span>
                      )}
                    </button>
                  </li>
                )
              })}
            </ul>
          </nav>

          <div className="flex-1 space-y-6">
            <div className="rounded-3xl border border-border/60 p-6 shadow-sm">
              <div className="space-y-3">
                <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.3em] text-muted-foreground">
                  {activeMeta?.icon ? <activeMeta.icon className="h-4 w-4 text-primary" /> : null}
                  <span>{activeMeta?.label}</span>
                </div>
                <div className="space-y-2">
                  <h1 className="text-2xl font-semibold text-foreground">{activeMeta?.title}</h1>
                  <p className="text-sm text-muted-foreground">{activeMeta?.description}</p>
                </div>
              </div>
            </div>

            {activeTab === 'shortcuts' && <ShortcutSettingsCard />}
            {activeTab === 'appearance' && (
              <div className="rounded-2xl border border-dashed border-muted-foreground/40 px-6 py-10 text-center text-sm text-muted-foreground">
                Appearance options are coming soon.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
