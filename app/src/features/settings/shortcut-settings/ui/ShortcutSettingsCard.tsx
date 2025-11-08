import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { toast } from 'sonner'

import { useShortcutRegistry } from '@/shared/contexts/shortcut-context'
import { chordFromEvent, resolveBindings } from '@/shared/lib/shortcuts'
import type { KeyBinding, ShortcutAction } from '@/shared/types/shortcuts'
import { Badge } from '@/shared/ui/badge'
import { Button } from '@/shared/ui/button'

import { useShortcutSettings } from '@/features/settings/shortcut-settings/model/useShortcutSettings'

type RecorderProps = {
  value: KeyBinding | null
  onCapture: (binding: KeyBinding) => void
  formatBinding: (binding: KeyBinding) => string
  disabled?: boolean
}

function ShortcutRecorder({ value, onCapture, formatBinding, disabled }: RecorderProps) {
  const [recording, setRecording] = useState(false)
  const { suspendDispatch } = useShortcutRegistry()
  const releaseSuspensionRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    if (recording && !releaseSuspensionRef.current) {
      releaseSuspensionRef.current = suspendDispatch()
    } else if (!recording && releaseSuspensionRef.current) {
      releaseSuspensionRef.current()
      releaseSuspensionRef.current = null
    }

    return () => {
      if (releaseSuspensionRef.current) {
        releaseSuspensionRef.current()
        releaseSuspensionRef.current = null
      }
    }
  }, [recording, suspendDispatch])

  useEffect(() => {
    if (!recording) return
    const handleKeyDown = (event: KeyboardEvent) => {
      event.preventDefault()
      event.stopPropagation()
      if (event.key === 'Escape') {
        setRecording(false)
        return
      }
      const chord = chordFromEvent(event)
      if (!chord) return
      setRecording(false)
      onCapture([chord])
    }
    window.addEventListener('keydown', handleKeyDown, true)
    return () => window.removeEventListener('keydown', handleKeyDown, true)
  }, [recording, onCapture])

  const label = recording ? 'Press keys…' : value ? formatBinding(value) : 'Not assigned'

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="min-w-[150px] rounded-lg border border-border/60 bg-muted/20 px-3 py-1 text-sm font-medium">
        {label}
      </span>
      <Button
        type="button"
        size="sm"
        variant={recording ? 'secondary' : 'outline'}
        onClick={() => setRecording((prev) => !prev)}
        disabled={disabled}
      >
        {recording ? 'Recording' : 'Record'}
      </Button>
    </div>
  )
}

type RowProps = {
  action: ShortcutAction
  binding: KeyBinding | null
  customized: boolean
  onChange: (binding: KeyBinding | null) => void
  formatBinding: (binding: KeyBinding) => string
  disabled?: boolean
}

function ShortcutRow({ action, binding, customized, onChange, formatBinding, disabled }: RowProps) {
  return (
    <div className="rounded-2xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-foreground">{action.label}</p>
          {action.description && <p className="text-xs text-muted-foreground">{action.description}</p>}
        </div>
        {customized && (
          <Badge variant="outline" className="rounded-full text-[11px]">
            Custom
          </Badge>
        )}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <ShortcutRecorder value={binding} onCapture={(val) => onChange(val)} formatBinding={formatBinding} disabled={disabled} />
        <Button type="button" size="sm" variant="ghost" onClick={() => onChange(null)} disabled={!customized || disabled}>
          Reset
        </Button>
      </div>
    </div>
  )
}

export function ShortcutSettingsCard() {
  const {
    actions,
    platform,
    formatBinding,
    draft,
    dirty,
    saving,
    handleBindingChange,
    resetDraft,
    resetToDefaults,
    save,
  } = useShortcutSettings()

  const grouped = useMemo(() => {
    const result = new Map<string, Array<{ action: ShortcutAction; binding: KeyBinding | null; customized: boolean }>>()
    for (const action of actions) {
      const binding = resolveBindings(action, draft, platform)[0] ?? null
      const customized = Boolean(draft[action.id]?.default?.length)
      const bucket = result.get(action.category) ?? []
      bucket.push({ action, binding, customized })
      result.set(action.category, bucket)
    }
    return result
  }, [actions, draft, platform])

  const handleSave = useCallback(async () => {
    try {
      await save()
      toast.success('Shortcuts updated')
    } catch (error) {
      console.error('[settings] save shortcuts failed', error)
      toast.error('Failed to update shortcuts')
    }
  }, [save])

  return (
    <div className="space-y-6">
      {Array.from(grouped.entries()).map(([category, entries]) => (
        <section key={category} className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{category}</p>
            <span className="text-[11px] text-muted-foreground/80">{entries.length} actions</span>
          </div>
          <div className="space-y-3">
            {entries.map(({ action, binding, customized }) => (
              <ShortcutRow
                key={action.id}
                action={action}
                binding={binding}
                customized={customized}
                onChange={(value) => handleBindingChange(action.id, value)}
                formatBinding={(bindingValue) => formatBinding(bindingValue)}
                disabled={saving}
              />
            ))}
          </div>
        </section>
      ))}

      <div className="flex flex-wrap justify-end gap-2 pt-2">
        <Button type="button" variant="destructive" onClick={resetToDefaults} disabled={saving}>
          Reset to defaults
        </Button>
        <Button type="button" variant="ghost" onClick={resetDraft} disabled={!dirty || saving}>
          Discard
        </Button>
        <Button type="button" onClick={handleSave} disabled={!dirty || saving}>
          {saving ? 'Saving…' : 'Save changes'}
        </Button>
      </div>
    </div>
  )
}
