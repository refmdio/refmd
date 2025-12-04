import type { LucideIcon } from 'lucide-react'
import { Command, GitCommit, Info, Sparkles, Users } from 'lucide-react'

export type SettingsNavItem = {
  id: string
  label: string
  description: string
  icon: LucideIcon
  to: string
}

export const settingsNavItems: SettingsNavItem[] = [
  {
    id: 'about',
    label: 'About RefMD',
    description: 'Overview, release highlights, and support links.',
    icon: Info,
    to: '/settings',
  },
  {
    id: 'shortcuts',
    label: 'Keyboard shortcuts',
    description: 'Customize editor key chords.',
    icon: Command,
    to: '/settings/shortcuts',
  },
  {
    id: 'visibility',
    label: 'Public pages',
    description: 'Manage workspace visibility and sharing.',
    icon: Users,
    to: '/settings/visibility',
  },
  {
    id: 'plugins',
    label: 'Plugins',
    description: 'Install and manage plugins.',
    icon: Sparkles,
    to: '/settings/plugins',
  },
  {
    id: 'git-sync',
    label: 'Git Sync',
    description: 'Repo sync & history.',
    icon: GitCommit,
    to: '/settings/git-sync',
  },
]
