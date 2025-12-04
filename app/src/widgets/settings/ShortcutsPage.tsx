import { settingsNavItems } from '@/features/settings/nav'

import { SettingsShell } from './SettingsShell'
import { ShortcutSettingsCard } from '@/features/settings/shortcut-settings/ui/ShortcutSettingsCard'

export default function ShortcutsPage() {
  return (
    <SettingsShell
      header={{
        eyebrow: 'Shortcuts',
        title: 'Keyboard shortcuts',
        description: 'Customize the key chords used across the editor and workspace navigation.',
      }}
      navItems={settingsNavItems}
    >
      <div className="space-y-4">
        <ShortcutSettingsCard />
      </div>
    </SettingsShell>
  )
}
