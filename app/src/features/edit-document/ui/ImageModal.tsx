import { X } from 'lucide-react'
import { useEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'

type Props = { src: string; alt?: string; isOpen: boolean; onClose: () => void }

export function ImageModal({ src, alt, isOpen, onClose }: Props) {
  const handleKeyDown = useCallback((e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }, [onClose])
  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown)
      const prev = document.body.style.overflow
      document.body.style.overflow = 'hidden'
      return () => { document.removeEventListener('keydown', handleKeyDown); document.body.style.overflow = prev }
    }
  }, [isOpen, handleKeyDown])
  if (!isOpen) return null

  const modal = (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm animate-in fade-in duration-200" onClick={onClose}>
      <div className="relative max-h-[90vh] max-w-[90vw]" onClick={(e) => e.stopPropagation()}>
        <button onClick={onClose} className="absolute -top-10 right-0 rounded-full bg-white/10 p-2 text-white transition-colors hover:bg-white/20" aria-label="Close image">
          <X className="h-6 w-6" />
        </button>
        <img src={src} alt={alt || 'Expanded image'} className="h-auto max-h-[90vh] w-auto max-w-full rounded-lg shadow-2xl animate-in zoom-in-95 duration-200" />
      </div>
    </div>
  )

  if (typeof document === 'undefined') return modal
  return createPortal(modal, document.body)
}

export default ImageModal
