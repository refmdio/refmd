import { createFileRoute } from '@tanstack/react-router'
import { Download, PackagePlus, Plug, RefreshCcw, Shield, Terminal } from 'lucide-react'
import { FormEvent, useMemo, useState } from 'react'
import { toast } from 'sonner'

import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Card, CardFooter } from '@/shared/ui/card'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'

import { installPluginFromUrl, pluginManifestQuery, uninstallPlugin, usePluginManifest } from '@/entities/plugin'

import { appBeforeLoadGuard } from '@/features/auth'

export const Route = createFileRoute('/(app)/plugins')({
  staticData: { layout: 'app' },
  beforeLoad: appBeforeLoadGuard,
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(pluginManifestQuery())
    return null
  },
  component: PluginsPage,
})

type PluginLike = (ReturnType<typeof usePluginManifest>['plugins'])[number]

type CommandLike = (ReturnType<typeof usePluginManifest>['commands'])[number]

function PluginsPage() {
  const { plugins, commands, loading, refresh } = usePluginManifest()
  const [installUrl, setInstallUrl] = useState('')
  const [installToken, setInstallToken] = useState('')
  const [installing, setInstalling] = useState(false)
  const [removingId, setRemovingId] = useState<string | null>(null)

  const { userPlugins, globalPlugins, commandsByScopeKey } = useMemo(() => {
    const scopeKey = (pluginId: string, scope?: string | null) =>
      `${pluginId}:${scope === 'user' ? 'user' : 'global'}`

    const commandBuckets = new Map<string, CommandLike[]>()
    for (const cmd of commands) {
      const key = scopeKey(cmd.pluginId, cmd.scope)
      const bucket = commandBuckets.get(key)
      if (bucket) bucket.push(cmd)
      else commandBuckets.set(key, [cmd])
    }

    const userList = plugins.filter((p) => (p as any)?.scope === 'user')
    const globalList = plugins.filter((p) => (p as any)?.scope !== 'user')

    return {
      userPlugins: userList,
      globalPlugins: globalList,
      commandsByScopeKey: commandBuckets,
    }
  }, [plugins, commands])

  const handleInstall = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const url = installUrl.trim()
    const token = installToken.trim()
    if (!url) {
      toast.error('Enter a plugin bundle URL.')
      return
    }
    setInstalling(true)
    try {
      await installPluginFromUrl(url, token || undefined)
      toast.success('Plugin installed.')
      setInstallUrl('')
      setInstallToken('')
      await refresh()
    } catch (error: any) {
      console.error('[plugins] install-from-url failed', error)
      toast.error(error?.message || 'Failed to install plugin.')
    } finally {
      setInstalling(false)
    }
  }

  const handleUninstall = async (pluginId: string) => {
    if (!pluginId) return
    setRemovingId(pluginId)
    try {
      await uninstallPlugin(pluginId)
      toast.success('Plugin uninstalled.')
      await refresh()
    } catch (error: any) {
      console.error('[plugins] uninstall failed', error)
      toast.error(error?.message || 'Failed to uninstall plugin.')
    } finally {
      setRemovingId((current) => (current === pluginId ? null : current))
    }
  }

  const totalCommands = commands.length

  const renderPluginSection = (
    title: string,
    list: PluginLike[],
    emptyMessage: string,
    allowUninstall = false,
  ) => (
    <section className="space-y-4">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <h2 className="text-lg font-semibold text-foreground">{title}</h2>
          <p className="text-sm text-muted-foreground">{list.length} installed</p>
        </div>
        <Badge variant="secondary" className="self-start rounded-full px-3 py-1">
          {list.length}
        </Badge>
      </div>
      {list.length === 0 ? (
        <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-muted-foreground/40 bg-muted/20 px-6 py-10 text-center text-sm text-muted-foreground">
          <Plug className="h-5 w-5 text-primary" />
          <p>{emptyMessage}</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {list.map((plugin) => {
            const scope = (plugin as any)?.scope === 'user' ? 'user' : 'global'
            const key = `${plugin.id}:${scope}`
            const pluginCommands = commandsByScopeKey.get(key) ?? []
            const author = (plugin as any)?.author as string | undefined
            const repository = (plugin as any)?.repository as string | undefined
            const isRemoving = removingId === plugin.id

            return (
              <Card
                key={`${plugin.id}_${scope}`}
                className="group flex h-full flex-col gap-4 border-border/70 p-5 shadow-sm transition-all duration-200 hover:-translate-y-1 hover:border-primary/40"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="truncate text-base font-semibold text-foreground" title={plugin.name ?? plugin.id}>
                      {plugin.name ?? plugin.id}
                    </h3>
                    <p className="text-xs text-muted-foreground">{plugin.id}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="uppercase">
                      {scope}
                    </Badge>
                    <Badge variant="outline">v{plugin.version}</Badge>
                  </div>
                </div>

                {(author || repository) && (
                  <div className="space-y-1 text-xs text-muted-foreground">
                    {author && (
                      <div>
                        <span className="text-foreground">Author:</span> {author}
                      </div>
                    )}
                    {repository && (
                      <div className="break-all">
                        <span className="text-foreground">Repository:</span>{' '}
                        <a className="underline" href={repository} target="_blank" rel="noreferrer">
                          {repository}
                        </a>
                      </div>
                    )}
                  </div>
                )}

                <div className="space-y-3 text-xs text-muted-foreground">
                  <div>
                    <p className="mb-1 text-xs font-semibold text-foreground/90">Mounts</p>
                    <div className="flex flex-wrap gap-2">
                      {(plugin.mounts ?? []).map((mount: string) => (
                        <Badge key={mount} variant="secondary" className="rounded-full px-2 py-0.5 text-[11px]">
                          {mount}
                        </Badge>
                      ))}
                      {(!plugin.mounts || plugin.mounts.length === 0) && <span>—</span>}
                    </div>
                  </div>
                  <div>
                    <p className="mb-1 text-xs font-semibold text-foreground/90">Permissions</p>
                    <div className="flex flex-wrap gap-2">
                      {(plugin.permissions ?? []).map((permission: string) => (
                        <Badge key={permission} variant="outline" className="rounded-full px-2 py-0.5 text-[11px]">
                          {permission}
                        </Badge>
                      ))}
                      {(!plugin.permissions || plugin.permissions.length === 0) && <span>—</span>}
                    </div>
                  </div>
                  <div>
                    <p className="mb-1 text-xs font-semibold text-foreground/90">Commands</p>
                    <div className="space-y-1">
                      {pluginCommands.length === 0 && <span>—</span>}
                      {pluginCommands.map((cmd) => (
                        <div key={cmd.action} className="flex items-center gap-2">
                          <Badge variant="secondary" className="rounded-full px-2 py-0.5 text-[11px]">
                            {cmd.action}
                          </Badge>
                          <span>{cmd.title}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {allowUninstall && (
                  <CardFooter className="mt-auto flex justify-end gap-2 border-t border-border/60 pt-4">
                    <Button
                      variant="ghost"
                      className="rounded-full px-4 text-destructive transition-colors hover:bg-destructive/10"
                      onClick={() => handleUninstall(plugin.id)}
                      disabled={isRemoving}
                    >
                      {isRemoving ? 'Removing…' : 'Remove'}
                    </Button>
                  </CardFooter>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </section>
  )

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-10 px-4 pb-20 pt-10 sm:px-6 md:px-8">
        <section className="rounded-3xl border border-border/60 p-6 shadow-lg backdrop-blur md:p-8">
          <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="space-y-2">
              <Badge variant="secondary" className="w-fit rounded-full px-3 py-1 text-xs font-medium uppercase tracking-wide">
                Plugins
              </Badge>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                Plugin dashboard
              </h1>
              <p className="text-sm text-muted-foreground">
                Quick status of your bundles, global installs, and exposed commands.
              </p>
            </div>
            <div className="grid gap-3 text-sm text-muted-foreground sm:grid-cols-3">
              <div className="flex items-center gap-2 rounded-2xl border border-border/70 bg-muted/30 px-4 py-3">
                <PackagePlus className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted-foreground/80">User plugins</p>
                  <p className="text-lg font-semibold text-foreground">{userPlugins.length}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 rounded-2xl border border-border/70 bg-muted/30 px-4 py-3">
                <Shield className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Global plugins</p>
                  <p className="text-lg font-semibold text-foreground">{globalPlugins.length}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 rounded-2xl border border-border/70 bg-muted/30 px-4 py-3">
                <Terminal className="h-4 w-4 text-primary" />
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Commands</p>
                  <p className="text-lg font-semibold text-foreground">{totalCommands}</p>
                </div>
              </div>
            </div>
          </div>
          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Button
              variant="outline"
              onClick={() => refresh()}
              disabled={loading}
              className="rounded-full px-4"
            >
              <RefreshCcw className="h-4 w-4" />
              <span className="ml-2 text-sm">{loading ? 'Refreshing…' : 'Refresh'}</span>
            </Button>
          </div>
        </section>

        <section className="rounded-3xl border border-border/60 p-6 shadow-sm backdrop-blur md:p-8">
          <div className="flex flex-col gap-4">
            <div>
              <h2 className="text-lg font-semibold text-foreground">Install from URL</h2>
              <p className="text-sm text-muted-foreground">Deploy a bundle by pointing to a hosted zip or tarball.</p>
            </div>
            <form
              onSubmit={handleInstall}
              className="grid gap-4 md:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_auto] md:items-end"
            >
              <div className="grid gap-2">
                <Label htmlFor="plugin-url" className="text-sm font-medium">Bundle URL</Label>
                <Input
                  id="plugin-url"
                  type="url"
                  placeholder="https://example.com/plugin.zip"
                  value={installUrl}
                  onChange={(event) => setInstallUrl(event.target.value)}
                  required
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="plugin-token" className="text-sm font-medium">Bearer token (optional)</Label>
                <Input
                  id="plugin-token"
                  type="text"
                  placeholder="Token if required"
                  value={installToken}
                  onChange={(event) => setInstallToken(event.target.value)}
                />
              </div>
              <Button type="submit" disabled={installing} className="rounded-full px-5">
                <Download className="h-4 w-4" />
                <span className="ml-2 text-sm">{installing ? 'Installing…' : 'Install plugin'}</span>
              </Button>
            </form>
          </div>
        </section>

        {renderPluginSection('User plugins', userPlugins, 'No user plugins installed yet.', true)}
        {renderPluginSection('Global plugins', globalPlugins, 'No global plugins available.')}
      </div>
    </div>
  )
}
