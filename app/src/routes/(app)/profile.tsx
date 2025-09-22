import { createFileRoute, Link } from '@tanstack/react-router'
import { ArrowRight, Globe, Mail, Shield, Users } from 'lucide-react'

import { Avatar, AvatarFallback } from '@/shared/ui/avatar'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card } from '@/shared/ui/card'

import { appBeforeLoadGuard, useAuthContext } from '@/features/auth'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'

export const Route = createFileRoute('/(app)/profile')({
  staticData: { layout: 'app' },
  pendingComponent: () => <RoutePending />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  beforeLoad: appBeforeLoadGuard,
  component: ProfilePage,
})

function ProfilePage() {
  const { user } = useAuthContext()
  const displayName = user?.name || 'User'
  const initials = displayName.slice(0, 1).toUpperCase()
  const email = user?.email || 'No email attached'
  const publicUrl = `/u/${encodeURIComponent(user?.name || '')}/`

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-8 px-4 pb-16 pt-10 sm:px-6 md:px-8">
        <section className="rounded-3xl border border-border/60 p-6 shadow-lg backdrop-blur md:p-8">
          <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="flex items-start gap-4">
              <Avatar className="h-16 w-16 text-lg">
                <AvatarFallback>{initials}</AvatarFallback>
              </Avatar>
              <div className="space-y-2">
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <h1 className="text-2xl font-semibold tracking-tight text-foreground">{displayName}</h1>
                    <Badge variant="secondary" className="rounded-full px-3 py-1 text-xs uppercase tracking-wide">
                      Workspace Owner
                    </Badge>
                  </div>
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Mail className="h-4 w-4" />
                    {email}
                  </p>
                </div>
                <p className="max-w-xl text-sm text-muted-foreground">
                  Manage how you appear across shared and public RefMD spaces. Update your public profile to make it easier for collaborators to find you.
                </p>
              </div>
            </div>
            <Button asChild variant="outline" className="mt-4 inline-flex items-center gap-2 rounded-full px-4 md:mt-0">
              <a href={publicUrl} target="_blank" rel="noopener noreferrer">
                <Users className="h-4 w-4" />
                View public profile
                <ArrowRight className="h-4 w-4" />
              </a>
            </Button>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-2">
          <Card className="border-border/60 p-6 shadow-sm">
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-primary" />
              <div className="space-y-2">
                <h2 className="text-base font-semibold text-foreground">Account security</h2>
                <p className="text-sm text-muted-foreground">
                  Your account is protected by workspace authentication. Sign out from other devices to keep things secure.
                </p>
                <Button variant="outline" size="sm" className="rounded-full px-4" disabled>
                  Manage sessions
                </Button>
              </div>
            </div>
          </Card>

          <Card className="border-border/60 p-6 shadow-sm">
            <div className="flex items-start gap-3">
              <Globe className="h-5 w-5 text-primary" />
              <div className="space-y-2">
                <h2 className="text-base font-semibold text-foreground">Public presence</h2>
                <p className="text-sm text-muted-foreground">
                  Configure which documents appear at your public URL and keep your published work up to date.
                </p>
                <Button asChild size="sm" className="rounded-full px-4">
                  <Link to="/visibility" className="inline-flex items-center gap-2">
                    Manage visibility
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              </div>
            </div>
          </Card>
        </section>
      </div>
    </div>
  )
}
