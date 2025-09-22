import type * as monacoNs from 'monaco-editor'
import { useCallback, useRef, useState } from 'react'

export function useScrollSync(editorRef: React.MutableRefObject<monacoNs.editor.IStandaloneCodeEditor | null>) {
  const isSyncingRef = useRef(false)
  const [previewScrollPct, setPreviewScrollPct] = useState<number | undefined>(undefined)
  const [previewAnchorLine, setPreviewAnchorLine] = useState<number | undefined>(undefined)
  const rafRef = useRef<number | null>(null)
  const pinnedEditorBottomRef = useRef<boolean>(false)
  const prevDenomRef = useRef<number>(0)
  const prevTopRef = useRef<number>(0)
  const lockUntilRef = useRef<number>(0)
  const [lockActive, setLockActive] = useState(false)
  const lockTimerRef = useRef<number | null>(null)

  const handleEditorScroll = useCallback((e: any) => {
    const ed = editorRef.current
    if (!ed) return
    if (isSyncingRef.current) return
    if (rafRef.current != null) cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      try {
        const height = ed.getScrollHeight?.() ?? 0
        const viewHeight = ed.getLayoutInfo?.().height ?? 0
        const denom = Math.max(1, height - viewHeight)
        const top = e?.scrollTop ?? ed.getScrollTop()
        const prevDenom = prevDenomRef.current || denom
        const prevTop = prevTopRef.current || 0

        // Heuristic: if content height grew but scrollTop barely changed,
        // treat this as content insertion (not user scroll) and anchor
        // preview percentage to previous denominator to avoid upward drift.
        const denomIncreased = denom > prevDenom + 0.5
        const topUnchanged = Math.abs(top - prevTop) <= 2
        const baselineDenom = (denomIncreased && topUnchanged) ? prevDenom : denom

        // Determine if editor was pinned to bottom as of previous metrics.
        const distFromBottomPrev = Math.max(0, prevDenom - prevTop)
        const pinnedPrev = distFromBottomPrev <= 4
        pinnedEditorBottomRef.current = pinnedPrev
        const now = Date.now()
        const locked = lockUntilRef.current > now
        // Visible top line for source-anchored sync
        let topLine: number | undefined
        try {
          const vrs = (ed as any).getVisibleRanges?.() || []
          if (vrs && vrs.length > 0) topLine = vrs[0].startLineNumber
          else topLine = (ed as any).getPosition?.()?.lineNumber
        } catch {}

        const pct = (pinnedPrev || locked)
          ? 1
          : Math.min(1, Math.max(0, top / baselineDenom))

        // Prefer anchor-line when not pinned/locked; else rely on bottom lock
        if (pinnedPrev || locked) setPreviewAnchorLine(undefined)
        else if (typeof topLine === 'number' && Number.isFinite(topLine)) setPreviewAnchorLine(topLine)
        else setPreviewAnchorLine(undefined)
        prevDenomRef.current = denom
        prevTopRef.current = top
        isSyncingRef.current = true
        setPreviewScrollPct(pct)
      } finally {
        setTimeout(() => { isSyncingRef.current = false }, 0)
        rafRef.current = null
      }
    })
  }, [editorRef])

  const handlePreviewScroll = useCallback((pct: number) => {
    const ed = editorRef.current
    if (!ed) return
    if (isSyncingRef.current) return
    try {
      isSyncingRef.current = true
      const height = ed.getScrollHeight?.() ?? 0
      const viewHeight = ed.getLayoutInfo?.().height ?? 0
      const denom = Math.max(1, height - viewHeight)
      const target = pct >= 0.999 ? denom : Math.round(denom * pct)
      ed.setScrollTop(target)
    } finally {
      isSyncingRef.current = false
    }
  }, [editorRef])

  const onEditorContentChange = useCallback(() => {
    if (pinnedEditorBottomRef.current) {
      lockUntilRef.current = Date.now() + 500
      setPreviewScrollPct(1)
      setPreviewAnchorLine(undefined)
      setLockActive(true)
      if (lockTimerRef.current) window.clearTimeout(lockTimerRef.current)
      lockTimerRef.current = window.setTimeout(() => setLockActive(false), 520)
    }
  }, [])

  const onCaretAtEndChange = useCallback((isAtEnd: boolean) => {
    if (isAtEnd) {
      lockUntilRef.current = Date.now() + 500
      setPreviewScrollPct(1)
      setPreviewAnchorLine(undefined)
      setLockActive(true)
      if (lockTimerRef.current) window.clearTimeout(lockTimerRef.current)
      lockTimerRef.current = window.setTimeout(() => setLockActive(false), 520)
    }
  }, [])

  return { previewScrollPct, previewAnchorLine, handleEditorScroll, handlePreviewScroll, onEditorContentChange, onCaretAtEndChange, lockActive }
}
