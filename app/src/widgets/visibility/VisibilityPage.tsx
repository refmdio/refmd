import { useQueryClient, useSuspenseQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Copy, Trash2, Link as LinkIcon, FileText, Globe, Link2, ShieldCheck, Sparkles } from 'lucide-react'
import React from 'react'
import { toast } from 'sonner'

import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'


import { useWorkspacePublicDocuments, unpublishDocument } from '@/entities/public'
import { activeSharesQuery, deleteShare } from '@/entities/share'

import { useAuthContext } from '@/features/auth'
import { settingsNavItems } from '@/features/settings/nav'
import { DocumentShareCard, FolderShareTree } from '@/features/sharing'
import type { ActiveShareItem } from '@/features/sharing'

import { SettingsShell } from '@/widgets/settings/SettingsShell'

export type PublicDoc = { id: string; title: string; updated_at: string; published_at: string }

export default function VisibilityPage() {
  const { user, activeWorkspace } = useAuthContext()
  const qc = useQueryClient()
  const { data: shareData } = useSuspenseQuery(activeSharesQuery())
  const activeSlug = activeWorkspace?.slug || user?.name || ''
  const { data: publicDocsData, isLoading: publicLoading } = useWorkspacePublicDocuments(activeSlug)
  const shares = (shareData ?? []) as ActiveShareItem[]
  const publicDocs = (publicDocsData ?? []) as PublicDoc[]

  const formatDate = React.useCallback((value: string) => {
    try {
      return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(value))
    } catch {
      return value
    }
  }, [])

  const copy = (text: string) => {
    navigator.clipboard
      .writeText(text)
      .then(() => toast.success('Copied'))
      .catch((error) => {
        console.error('[visibility] failed to copy', error)
        toast.error('Copy failed')
      })
  }

  const removeShare = async (token: string) => {
    try {
      await deleteShare(token)
      toast.success('Share removed')
      qc.invalidateQueries({ queryKey: activeSharesQuery().queryKey })
    } catch (error) {
      console.error('[visibility] remove share failed', error)
      toast.error('Failed to remove')
    }
  }

  const unpublish = async (id: string) => {
    try {
      await unpublishDocument(id)
      toast.success('Unpublished')
      qc.invalidateQueries()
    } catch (error) {
      console.error('[visibility] unpublish failed', error)
      toast.error('Failed to unpublish')
    }
  }

  const siteBase = React.useMemo(() => {
    if (typeof window === 'undefined') return ''
    return window.location.origin
  }, [])

  const buildPublicPath = React.useCallback(
    (docId: string) => {
      if (activeWorkspace?.slug) {
        return `/w/${encodeURIComponent(activeWorkspace.slug)}/${docId}`
      }
      if (user?.name) {
        return `/u/${encodeURIComponent(user.name)}/${docId}`
      }
      return `/w/${docId}`
    },
    [activeWorkspace?.slug, user?.name],
  )

  const filteredShares = React.useMemo(
    () => shares.filter((s) => s.document_type === 'folder' || !s.parent_share_id),
    [shares],
  )

  return (
    <SettingsShell
      header={{
        eyebrow: 'Visibility',
        title: 'Public exposure overview',
        description: 'Keep an eye on what is currently shared outside the workspace.',
      }}
      navItems={settingsNavItems}
    >
      <div className="space-y-10">
        <section className="grid gap-3 text-sm text-muted-foreground sm:grid-cols-2">
          <div className="flex items-center gap-2 rounded-2xl border border-border/70 bg-muted/30 px-4 py-3">
            <Globe className="h-4 w-4 text-primary" />
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Public documents</p>
              <p className="text-lg font-semibold text-foreground">{publicDocs.length}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-2xl border border-border/70 bg-muted/30 px-4 py-3">
            <Link2 className="h-4 w-4 text-primary" />
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground/80">Share links</p>
              <p className="text-lg font-semibold text-foreground">{filteredShares.length}</p>
            </div>
          </div>
        </section>

        <section className="space-y-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div className="space-y-1">
              <h2 className="flex items-center gap-2 text-lg font-semibold text-foreground">
                <Globe className="h-5 w-5 text-primary" /> Public documents
              </h2>
              <p className="text-sm text-muted-foreground">
                Items published to `@{user?.name || 'user'}` stay visible until you revoke them here.
              </p>
            </div>
            <Badge variant="secondary" className="self-start rounded-full px-3 py-1">{publicDocs.length}</Badge>
          </div>

          <div className="space-y-4">
            {publicLoading ? (
              <div className="grid gap-3">
                {[0, 1, 2].map((i) => (
                  <div key={i} className="h-20 animate-pulse rounded-2xl border border-dashed border-muted-foreground/30 bg-muted/20" />
                ))}
              </div>
            ) : publicDocs.length === 0 ? (
              <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-muted-foreground/40 bg-muted/20 px-6 py-10 text-center text-sm text-muted-foreground">
                <Sparkles className="h-6 w-6 text-primary" />
                <div className="space-y-1">
                  <p className="text-base font-medium text-foreground">No public documents yet</p>
                  <p>Publish a document to share it with the world.</p>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {publicDocs.map((doc) => {
                  const openUrl = buildPublicPath(doc.id)
                  const full = `${siteBase}${openUrl}`
                  return (
                    <div
                      key={doc.id}
                      className="group flex flex-col gap-4 rounded-xl border border-border/70 bg-card p-5 text-card-foreground shadow-sm transition-all duration-200 hover:-translate-y-1 hover:border-primary/40"
                    >
                      <div className="flex flex-wrap justify-between gap-2">
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2 text-sm font-medium text-card-foreground">
                            <FileText className="h-4 w-4 text-primary" />
                            <span className="truncate">{doc.title}</span>
                            <Badge variant="outline">Public</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground">Published {formatDate(doc.published_at)}</p>
                        </div>
                        <div className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                          <span className="rounded-full bg-muted px-2 py-0.5">{formatDate(doc.updated_at)}</span>
                          <span>Last updated</span>
                        </div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        <LinkIcon className="mr-1 inline h-3 w-3" />
                        {full}
                      </div>
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        <Button size="sm" variant="outline" asChild className="rounded-full px-3">
                          <Link to={openUrl as any}>Open</Link>
                        </Button>
                        <Button size="sm" variant="outline" className="rounded-full px-3" onClick={() => copy(full)}>
                          <Copy className="h-4 w-4" />
                          <span className="ml-1 text-xs">Copy</span>
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="rounded-full px-3 text-destructive transition-colors hover:bg-destructive/10"
                          onClick={() => unpublish(doc.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                          <span className="ml-1 text-xs">Unpublish</span>
                        </Button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </section>

        <section className="space-y-4">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
            <div className="space-y-1">
              <h2 className="flex items-center gap-2 text-lg font-semibold text-foreground">
                <Link2 className="h-5 w-5 text-primary" /> Share links
              </h2>
              <p className="text-sm text-muted-foreground">
                Active links remain accessible until they expire or you remove them.
              </p>
            </div>
            <Badge variant="secondary" className="self-start rounded-full px-3 py-1">{filteredShares.length}</Badge>
          </div>

          <div className="space-y-4">
            {shares.length === 0 ? (
              <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-muted-foreground/40 bg-muted/20 px-6 py-10 text-center text-sm text-muted-foreground">
                <ShieldCheck className="h-6 w-6 text-primary" />
                <div className="space-y-1">
                  <p className="text-base font-medium text-foreground">No active share links</p>
                  <p>Create a share link from a document to collaborate securely.</p>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredShares.map((share) => {
                  if (share.document_type === 'folder') {
                    return (
                      <FolderShareTree
                        key={share.id}
                        share={share}
                        allShares={shares}
                        siteOrigin={siteBase}
                        onCopy={copy}
                        onRemove={removeShare}
                      />
                    )
                  }
                  return (
                    <DocumentShareCard
                      key={share.id}
                      id={share.id}
                      documentTitle={share.document_title}
                      permission={share.permission}
                      url={share.url}
                      localUrl={`/document/${share.document_id}?token=${share.token}`}
                      expiresAt={share.expires_at}
                      fromFolder={!!share.parent_share_id}
                      onCopy={copy}
                      onRemove={removeShare}
                      token={share.token}
                    />
                  )
                })}
              </div>
            )}
          </div>
        </section>
      </div>
    </SettingsShell>
  )
}
