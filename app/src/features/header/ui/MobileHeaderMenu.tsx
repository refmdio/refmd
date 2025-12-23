import { Link } from '@tanstack/react-router'
import { Blocks, FileText, Github, LogOut, Share2, Sun, X } from 'lucide-react'

import type { DocumentHeaderAction } from '@/shared/types/document'
import { Button } from '@/shared/ui/button'

type MobileHeaderMenuProps = {
  open: boolean
  onClose: () => void
  canShare: boolean
  onShare: () => void
  onToggleTheme: () => void
  onSignOut: () => void
  documentActions?: DocumentHeaderAction[]
}

export function MobileHeaderMenu({
  open,
  onClose,
  canShare,
  onShare,
  onToggleTheme,
  onSignOut,
  documentActions = [],
}: MobileHeaderMenuProps) {
  if (!open) return null

  return (
    <>
      <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 md:hidden" onClick={onClose} />
      <div className="fixed inset-y-0 right-0 w-64 bg-background border-l shadow-xl z-50 md:hidden">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Menu</h2>
          <Button onClick={onClose} variant="ghost" className="h-8 w-8">
            <X className="h-5 w-5" />
          </Button>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex flex-col gap-2">
            <Button asChild variant="ghost" className="justify-start">
              <Link to="/dashboard">
                <FileText className="h-4 w-4 mr-2" /> Dashboard
              </Link>
            </Button>
            <Button asChild variant="ghost" className="justify-start">
              <Link to="/settings/plugins">
                <Blocks className="h-4 w-4 mr-2" /> Plugins
              </Link>
            </Button>
            <Button asChild variant="ghost" className="justify-start">
              <a href="https://github.com" target="_blank" rel="noopener noreferrer">
                <Github className="h-4 w-4 mr-2" /> GitHub
              </a>
            </Button>
          </div>

          <div className="flex flex-col gap-2 border-t pt-4">
            <Button onClick={onToggleTheme} variant="ghost" className="justify-start">
              <Sun className="h-4 w-4 mr-2" /> Toggle Theme
            </Button>
            {canShare && (
              <Button onClick={() => { onShare(); onClose() }} variant="ghost" className="justify-start">
                <Share2 className="h-4 w-4 mr-2" /> Share
              </Button>
            )}
            {documentActions.map((action) => (
              <Button
                key={action.id ?? action.label}
                onClick={() => { action.onSelect?.(); onClose() }}
                variant={action.variant === 'primary' ? 'default' : action.variant === 'outline' ? 'outline' : 'ghost'}
                className="justify-start"
                disabled={action.disabled}
              >
                {action.icon}
                {action.label}
              </Button>
            ))}
            <Button onClick={onSignOut} variant="ghost" className="justify-start">
              <LogOut className="h-4 w-4 mr-2" /> Sign out
            </Button>
          </div>
        </div>
      </div>
    </>
  )
}
