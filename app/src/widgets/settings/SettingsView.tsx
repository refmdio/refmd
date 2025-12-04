import { Badge } from '@/shared/ui/badge'
import { Card } from '@/shared/ui/card'
import { Separator } from '@/shared/ui/separator'

import { settingsNavItems } from '@/features/settings/nav'

import { SettingsShell } from './SettingsShell'

export default function SettingsView() {
  return (
    <SettingsShell
      header={{
        eyebrow: 'RefMD',
        title: 'About RefMD',
        description: 'See what is new, and where to file bugs or ask for help.',
      }}
      navItems={settingsNavItems}
    >
      <div className="space-y-6">
        <Card className="border-border/60 p-6 shadow-sm">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
              <Badge variant="secondary" className="rounded-full px-3 py-1 text-[11px]">Overview</Badge>
              <span>RefMD workspace</span>
            </div>
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>RefMD keeps documents, plugins, and sharing controls in one place so teams stay aligned.</p>
              <p>Use the navigation on the left to fine-tune shortcuts, manage public pages, and install plugins without leaving Settings.</p>
            </div>
          </div>
        </Card>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="border-border/60 p-6 shadow-sm">
            <div className="space-y-3">
              <Badge variant="secondary" className="rounded-full px-3 py-1 text-[11px] uppercase tracking-wide">What&apos;s new</Badge>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>- Plugins, visibility, and shortcuts now live under unified <span className="font-medium text-foreground">/settings</span>.</li>
                <li>- Plugin dashboard has a manual refresh and consistent navigation.</li>
                <li>- Visibility overview keeps public docs and share links in one place.</li>
              </ul>
            </div>
          </Card>

          <Card className="border-border/60 p-6 shadow-sm">
            <div className="space-y-3">
              <Badge variant="secondary" className="rounded-full px-3 py-1 text-[11px] uppercase tracking-wide">Core benefits</Badge>
              <div className="space-y-2 text-sm text-muted-foreground">
                <p className="font-medium text-foreground">Faster collaboration</p>
                <p>Share securely with visibility controls and shortcut profiles that travel with you.</p>
                <Separator className="my-2" />
                <p className="font-medium text-foreground">Extensible by design</p>
                <p>Plugin bundles add UI, commands, and file-tree icons tailored to your workflows.</p>
              </div>
            </div>
          </Card>
        </div>

        <Card className="border-border/60 p-6 shadow-sm">
          <div className="space-y-3">
            <Badge variant="secondary" className="rounded-full px-3 py-1 text-[11px] uppercase tracking-wide">Feedback & support</Badge>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>
                - Found a bug? Open an issue with steps to reproduce, the expected result, and what actually happened on{' '}
                <a
                  href="https://github.com/refmdio/refmd/issues"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-foreground"
                >
                  GitHub Issues
                </a>
                .
              </li>
              <li>- Feature requests are welcome there too—clear titles and labels help us triage faster.</li>
              <li>- For security or workspace-specific questions, reach out to your admins or team leads.</li>
            </ul>
          </div>
        </Card>
      </div>
    </SettingsShell>
  )
}
