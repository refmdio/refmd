import { useCallback, useRef, useState } from 'react'

import type { DocumentNode } from '@/features/file-tree'

type DragState = {
  draggedItem: string | null
  dropTarget: string | null
  isExternalDrag: boolean
}

type UseFileTreeDragProps = {
  onMove: (nodeId: string, targetId?: string) => Promise<void>
  onFileUpload?: (files: File[], parentId?: string) => Promise<void>
}

export function useFileTreeDrag({ onMove, onFileUpload }: UseFileTreeDragProps) {
  const [dragState, setDragState] = useState<DragState>({ draggedItem: null, dropTarget: null, isExternalDrag: false })
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleDragStart = useCallback((e: React.DragEvent, nodeId: string) => {
    setDragState({ draggedItem: nodeId, dropTarget: null, isExternalDrag: false })
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', nodeId)
  }, [])

  const handleDragEnd = useCallback(() => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    timeoutRef.current = setTimeout(() => setDragState({ draggedItem: null, dropTarget: null, isExternalDrag: false }), 50)
  }, [])

  const handleDragEnter = useCallback((e: React.DragEvent, nodeId: string, nodeType: DocumentNode['type']) => {
    e.preventDefault(); e.stopPropagation()
    const hasFiles = e.dataTransfer?.types.includes('Files')
    if (hasFiles) {
      if (nodeType === 'folder' || nodeId === '') {
        setDragState((s) => ({ ...s, dropTarget: nodeId, isExternalDrag: true }))
      }
      return
    }
    const hasInternal = e.dataTransfer?.types.includes('text/plain')
    const isRoot = nodeId === ''
    if ((nodeType === 'folder' || isRoot) && hasInternal && dragState.draggedItem !== nodeId) {
      setDragState((s) => ({ ...s, dropTarget: nodeId }))
    }
  }, [dragState.draggedItem])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault(); e.stopPropagation()
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    const target = e.currentTarget as HTMLElement
    timeoutRef.current = setTimeout(() => {
      const rect = target.getBoundingClientRect()
      const { clientX: x, clientY: y } = e
      const outside = x < rect.left || x > rect.right || y < rect.top || y > rect.bottom
      if (outside) setDragState((s) => ({ ...s, dropTarget: null, isExternalDrag: false }))
    }, 100)
  }, [])

  const handleDragOver = useCallback((e: React.DragEvent, nodeId?: string, nodeType?: DocumentNode['type']) => {
    e.preventDefault()
    const hasFiles = e.dataTransfer?.types.includes('Files')
    e.dataTransfer.dropEffect = hasFiles ? 'copy' : 'move'
    if (nodeId !== undefined && (nodeType === 'folder' || nodeId === '')) {
      const hasInternal = e.dataTransfer?.types.includes('text/plain')
      if (hasFiles || hasInternal) {
        if (dragState.draggedItem !== nodeId) setDragState((s) => ({ ...s, dropTarget: nodeId }))
      }
    }
  }, [dragState.draggedItem])

  const handleDrop = useCallback(async (e: React.DragEvent, targetId?: string, nodeType?: DocumentNode['type'], parentId?: string) => {
    e.preventDefault(); e.stopPropagation()
    const files = Array.from(e.dataTransfer?.files || [])
    if (files.length > 0 && onFileUpload) {
      const uploadParent = nodeType === 'folder' ? targetId : parentId
      await onFileUpload(files, uploadParent)
    } else {
      const draggedId = e.dataTransfer.getData('text/plain') || dragState.draggedItem
      if (draggedId && draggedId !== targetId) {
        if (targetId === undefined || nodeType === 'folder') {
          await onMove(draggedId, targetId)
        }
      }
    }
    setDragState({ draggedItem: null, dropTarget: null, isExternalDrag: false })
  }, [dragState.draggedItem, onMove, onFileUpload])

  return { dragState, handleDragStart, handleDragEnd, handleDragEnter, handleDragLeave, handleDragOver, handleDrop }
}
