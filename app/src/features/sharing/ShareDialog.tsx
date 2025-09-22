import { useQueryClient } from '@tanstack/react-query'
import { Copy, Users, Clock, Eye, Edit, Settings, Trash2, ExternalLink, Globe, Lock } from 'lucide-react'
import React, { useState, useEffect, useCallback } from 'react'
import { toast } from 'sonner'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'
import { Label } from '@/shared/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/shared/ui/select'
import { Separator } from '@/shared/ui/separator'
import { Switch } from '@/shared/ui/switch'

import { getPublishStatus, publishDocument, unpublishDocument } from '@/entities/public'
import { createShare, deleteShare, listDocumentShares, shareKeys } from '@/entities/share'

type ShareLink = {
  id: string
  token: string
  permission: string
  expires_at?: string
  url: string
  used_count?: number
  max_uses?: number
  scope?: 'document' | 'folder'
  parent_share_id?: string | null
}
type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  targetId: string
  targetType?: 'document' | 'folder'
}

const PERMISSION_ICONS = { view: Eye, edit: Edit, admin: Settings } as const
const PERMISSION_LABELS = { view: 'View only', edit: 'Can edit', admin: 'Admin' } as const

export default function ShareDialog({ open, onOpenChange, targetId, targetType = 'document' }: Props) {
  if (!targetId) {
    throw new Error('ShareDialog requires a targetId')
  }

  const qc = useQueryClient()

  const [permissionLevel, setPermissionLevel] = useState<string>('edit')
  const [shareLinks, setShareLinks] = useState<ShareLink[]>([])
  const [loading, setLoading] = useState(false)
  const [linkExpiry, setLinkExpiry] = useState<string>('7d')
  const [publishState, setPublishState] = useState({ isPublished: false, url: '', loading: false })

  const baseUrl = React.useMemo(() => (typeof window !== 'undefined' ? window.location.origin : ''), [])

  const loadShareLinks = useCallback(async () => {
    if (!targetId) return
    try {
      const links = await listDocumentShares(targetId)
      setShareLinks(links as any)
    } catch {}
  }, [targetId])

  useEffect(() => {
    if (open) {
      loadShareLinks()
    }
  }, [open, loadShareLinks])

  useEffect(() => {
    if (!open || !targetId || targetType === 'folder') return
    ;(async () => {
      try {
        const status = await getPublishStatus(targetId)
        if (status?.public_url) {
          setPublishState({ isPublished: true, url: status.public_url, loading: false })
        } else {
          setPublishState((p) => ({ ...p, isPublished: false, url: '' }))
        }
      } catch {
        setPublishState((p) => ({ ...p, isPublished: false, url: '' }))
      }
    })()
  }, [open, targetId, targetType])

  const createShareLink = async () => {
    setLoading(true)
    try {
      const req: any = { document_id: targetId, permission: permissionLevel }
      if (linkExpiry !== 'never') { const h = { '1h':1,'24h':24,'7d':168,'30d':720 }[linkExpiry] || 168; const d=new Date(); d.setHours(d.getHours()+h); req.expires_at=d.toISOString() }
      const result = await createShare(req)
      if (result?.token) { await loadShareLinks(); toast.success('Share link created') }
    } catch { toast.error('Failed to create share link') } finally { setLoading(false) }
  }
  const deleteShareLink = async (link: ShareLink) => {
    try {
      await deleteShare(link.token)
      setShareLinks(shareLinks.filter(l => l.token !== link.token))
      qc.invalidateQueries({ queryKey: shareKeys.active() })
      toast.success('Share link deleted')
    } catch {
      toast.error('Failed to update share link')
    }
  }
  const copyToClipboard = async (text: string) => { try { await navigator.clipboard.writeText(text); toast.success('Copied to clipboard') } catch { toast.error('Failed to copy') } }
  const copyPublicUrl = () => { if (publishState.url) copyToClipboard(`${baseUrl}${publishState.url}`) }
  const openPublicPage = () => { if (publishState.url) window.open(`${baseUrl}${publishState.url}`, '_blank') }
  const handlePublish = async () => { setPublishState(p=>({...p,loading:true})); try{ const r=await publishDocument(targetId); setPublishState({isPublished:true,url:r.public_url,loading:false}); toast.success('Published successfully')}catch{ setPublishState(p=>({...p,loading:false})); toast.error('Failed to publish')} }
  const handleUnpublish = async () => { setPublishState(p=>({...p,loading:true})); try{ await unpublishDocument(targetId); setPublishState({isPublished:false,url:'',loading:false}); toast.success('Unpublished successfully')}catch{ setPublishState(p=>({...p,loading:false})); toast.error('Failed to unpublish')} }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col', overlayPanelClass)}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Share {targetType === 'folder' ? 'Folder' : 'Document'}
          </DialogTitle>
          <DialogDescription>
            Create share links to give others access to this {targetType === 'folder' ? 'folder' : 'document'}
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-auto p-4 space-y-6">
          {targetType !== 'folder' && (
            <>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-sm font-medium flex items-center gap-2">
                      {publishState.isPublished ? (
                        <>
                          <Globe className="w-4 h-4 text-green-600" />
                          Public Document
                        </>
                      ) : (
                        <>
                          <Lock className="w-4 h-4 text-gray-600" />
                          Private Document
                        </>
                      )}
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      {publishState.isPublished
                        ? 'This document is publicly accessible at a permanent URL'
                        : 'Make this document publicly accessible without requiring a share link'}
                    </p>
                  </div>
                  <Switch id="pub" checked={publishState.isPublished} disabled={publishState.loading}
                    onCheckedChange={(v) => { v ? handlePublish() : handleUnpublish() }} />
                </div>
                {publishState.isPublished && publishState.url && (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground">Public URL</Label>
                    <div className="flex gap-2">
                      <Input value={`${baseUrl}${publishState.url}`} readOnly className="flex-1 font-mono text-sm bg-muted" />
                      <Button variant="outline" size="sm" onClick={copyPublicUrl}><Copy className="h-4 w-4" /></Button>
                      <Button variant="outline" size="sm" onClick={openPublicPage}><ExternalLink className="h-4 w-4" /></Button>
                    </div>
                  </div>
                )}
              </div>
              <Separator />
            </>
          )}

          <div className="space-y-3">
            <h4 className="font-medium">Temporary Share Links</h4>
            <p className="text-sm text-muted-foreground">Create temporary links with expiration dates and specific permissions</p>
            <div className="flex gap-2 items-center">
              <Select value={permissionLevel} onValueChange={setPermissionLevel}>
                <SelectTrigger className="w-[160px]"><SelectValue placeholder="Permission" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="view">View only</SelectItem>
                  <SelectItem value="edit">Can edit</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
              <Select value={linkExpiry} onValueChange={setLinkExpiry}>
                <SelectTrigger className="w-[160px]"><SelectValue placeholder="Expires" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">1 hour</SelectItem>
                  <SelectItem value="24h">24 hours</SelectItem>
                  <SelectItem value="7d">7 days</SelectItem>
                  <SelectItem value="30d">30 days</SelectItem>
                  <SelectItem value="never">Never expires</SelectItem>
                </SelectContent>
              </Select>
              <Button onClick={createShareLink} disabled={loading} className="flex-1">Create Share Link</Button>
            </div>
          </div>

          <div className="space-y-2">
            <h4 className="font-medium">Active temporary links</h4>
            {shareLinks.length === 0 ? (
              <p className="text-sm text-muted-foreground">No temporary share links created yet.</p>
            ) : (
              shareLinks.map((link) => {
                const Icon = (PERMISSION_ICONS as any)[link.permission] || Eye
                const sampleUrl = targetType === 'folder' ? `${baseUrl}/share/${link.token}` : link.url
                return (
                  <div key={link.id || link.token} className="p-3 border rounded-md space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="gap-1"><Icon className="h-3 w-3" />{(PERMISSION_LABELS as any)[link.permission] || link.permission}</Badge>
                        {link.scope === 'folder' && (<Badge variant="secondary">Folder</Badge>)}
                        {link.scope !== 'folder' && !!link.parent_share_id && (<Badge variant="secondary">From folder</Badge>)}
                      </div>
                      <div className="flex items-center gap-2">
                        {link.expires_at ? (<div className="flex items-center gap-1 text-sm text-muted-foreground"><Clock className="h-3 w-3" />Expires {new Date(link.expires_at).toLocaleDateString()}</div>) : (<div className="flex items-center gap-1 text-sm text-muted-foreground"><Clock className="h-3 w-3" />Never expires</div>)}
                        <Button variant="ghost" size="sm" onClick={() => deleteShareLink(link)} className="text-destructive hover:text-destructive"><Trash2 className="h-4 w-4" /></Button>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Input value={sampleUrl} readOnly className="flex-1 font-mono text-sm" />
                      <Button variant="outline" size="sm" onClick={() => copyToClipboard(sampleUrl)}><Copy className="h-4 w-4" /></Button>
                    </div>
                    <div className="text-xs text-muted-foreground">{`Used ${link.used_count || 0} times`}{link.max_uses ? ` (max ${link.max_uses})` : ''}</div>
                  </div>
                )
              })
            )}
          </div>

        </div>
        <DialogFooter>
          <div className="flex items-center gap-2 w-full">
            <div className="flex items-center gap-2 text-sm text-muted-foreground"><Users className="h-4 w-4 text-green-600" />1 user active</div>
            <div className="flex-1" />
            <Button variant="outline" onClick={() => onOpenChange(false)}>Done</Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
