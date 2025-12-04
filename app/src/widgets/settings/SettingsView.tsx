import { Badge } from '@/shared/ui/badge'
import { Card } from '@/shared/ui/card'

import { SettingsShell } from './SettingsShell'

export default function SettingsView() {
  return (
    <SettingsShell
      header={{
        eyebrow: 'RefMD',
        title: 'About RefMD',
        description: 'Learn what is new and how to get the most out of RefMD.',
      }}
    >
      <div className="space-y-4">
        <Card className="border-border/60 p-6 shadow-sm">
          <div className="space-y-3">
            <Badge variant="secondary" className="rounded-full px-3 py-1 text-xs uppercase tracking-wide">
              Overview
            </Badge>
            <p className="text-sm text-muted-foreground">
              RefMD keeps your documents, plugins, and sharing settings in one place. Use the navigation on the left to jump to keyboard shortcuts, public pages, or plugins without leaving the Settings area.
            </p>
            <p className="text-sm text-muted-foreground">
              This page will highlight release notes and platform updates so your team can stay aligned.
            </p>
          </div>
        </Card>
      </div>
    </SettingsShell>
  )
}
