import { useNavigate } from '@tanstack/react-router'
import { FileText, Hash } from 'lucide-react'
import React from 'react'

import { overlayPanelClass } from '@/shared/lib/overlay-classes'
import { cn } from '@/shared/lib/utils'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/shared/ui/dialog'
import { Input } from '@/shared/ui/input'

import { listDocuments } from '@/entities/document'
import { listTags } from '@/entities/tag'

type Props = { open: boolean; onOpenChange: (open: boolean) => void; presetTag?: string | null }

export default function SearchDialog({ open, onOpenChange, presetTag }: Props) {
  const navigate = useNavigate()
  const [q, setQ] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const [docs, setDocs] = React.useState<{ id: string; title: string }[]>([])
  const [tags, setTags] = React.useState<{ name: string; count: number }[]>([])
  const [selectedTag, setSelectedTag] = React.useState<string | null>(null)

  // fetch tags when opened
  React.useEffect(() => {
    if (!open) return
    ;(async () => {
      try {
        const items = await listTags(undefined) as any as { name: string; count: number }[]
        setTags(items || [])
      } catch { setTags([]) }
    })()
  }, [open])

  // apply preset tag when dialog opens or preset changes
  React.useEffect(() => {
    if (open && presetTag) {
      setSelectedTag(presetTag)
    }
  }, [open, presetTag])

  // fetch documents by title or selected tag
  React.useEffect(() => {
    let active = true
    const t = setTimeout(async () => {
      setLoading(true)
      try {
        const qq = q.trim()
        const params: any = {}
        if (selectedTag && selectedTag.length > 0) params.tag = selectedTag
        else if (qq) params.query = qq
        const res = await listDocuments(params as any)
        const items = (res.items || []) as { id: string; title: string }[]
        if (active) setDocs(items)
      } catch {
        if (active) setDocs([])
      } finally {
        if (active) setLoading(false)
      }
    }, 200)
    return () => { active = false; clearTimeout(t) }
  }, [q, selectedTag])

  const filteredTags = tags.filter(t => !q || t.name.toLowerCase().includes(q.toLowerCase()))
  const filteredDocs = docs
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={cn('text-foreground sm:max-w-lg w-[92vw] rounded-md border p-0 overflow-hidden', overlayPanelClass)}>
        <div className="px-4 pt-4 pb-2 border-b">
          <DialogTitle className="text-base font-semibold">Search</DialogTitle>
          <DialogDescription className="text-xs text-muted-foreground">Search documents and tags</DialogDescription>
        </div>
        <div className="px-4 pb-3">
          <Input placeholder="Search documents, tags..." value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="max-h-80 overflow-auto">
          <div className="px-4 text-xs text-muted-foreground mb-1">Tags</div>
          <ul className="px-2 pb-2 space-y-1">
            {filteredTags.map((t) => (
              <li key={t.name}
                className="flex items-center gap-2 px-2 py-1 rounded hover:bg-accent cursor-pointer"
                onClick={() => setSelectedTag(t.name)}
              >
                <Hash className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm flex-1 truncate">{t.name}</span>
                <span className="text-xs text-muted-foreground">{t.count}</span>
              </li>
            ))}
          </ul>
          <div className="px-4 text-xs text-muted-foreground mt-2 mb-1">Documents {selectedTag ? `tag:${selectedTag}` : ''}</div>
          <ul className="px-2 pb-4 space-y-1">
            {loading && <li className="px-2 py-1 text-xs text-muted-foreground">Searching…</li>}
            {!loading && filteredDocs.length === 0 && (
              <li className="px-2 py-1 text-xs text-muted-foreground">No results</li>
            )}
            {!loading && filteredDocs.map((d) => (
              <li
                key={d.id}
                className="flex items-center gap-2 px-2 py-1 rounded hover:bg-accent cursor-pointer"
                onClick={() => { onOpenChange(false); navigate({ to: '/document/$id', params: { id: d.id } }) }}
              >
                <FileText className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm truncate">{d.title}</span>
              </li>
            ))}
          </ul>
        </div>
      </DialogContent>
    </Dialog>
  )
}
