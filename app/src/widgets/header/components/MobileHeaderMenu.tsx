import { Link } from '@tanstack/react-router'
import { Blocks, Columns, Eye, FileCode, FileText, Github, LogOut, Share2, Sun, X } from 'lucide-react'

import { Button } from '@/shared/ui/button'

type MobileHeaderMenuProps = {
  open: boolean
  onClose: () => void
  showEditorFeatures: boolean
  headerViewMode: 'editor' | 'split' | 'preview'
  changeView: (mode: 'editor' | 'split' | 'preview') => void
  isCompact: boolean
  canShare: boolean
  onShare: () => void
  onToggleTheme: () => void
  onSignOut: () => void
}

export function MobileHeaderMenu({
  open,
  onClose,
  showEditorFeatures,
  headerViewMode,
  changeView,
  isCompact,
  canShare,
  onShare,
  onToggleTheme,
  onSignOut,
}: MobileHeaderMenuProps) {
  if (!open) return null

  const handleSelect = (mode: 'editor' | 'split' | 'preview') => {
    changeView(mode)
    onClose()
  }

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
          {showEditorFeatures && (
            <div className="border-b pb-4">
              <h3 className="text-sm font-medium mb-2">View Mode</h3>
              <div className="flex flex-col gap-2">
                <Button
                  onClick={() => handleSelect('editor')}
                  variant={headerViewMode === 'editor' ? 'secondary' : 'ghost'}
                  className="w-full justify-start"
                >
                  <FileCode className="h-4 w-4 mr-2" /> Editor only
                </Button>
                {!isCompact && (
                  <Button
                    onClick={() => handleSelect('split')}
                    variant={headerViewMode === 'split' ? 'secondary' : 'ghost'}
                    className="w-full justify-start"
                  >
                    <Columns className="h-4 w-4 mr-2" /> Split view
                  </Button>
                )}
                <Button
                  onClick={() => handleSelect('preview')}
                  variant={headerViewMode === 'preview' ? 'secondary' : 'ghost'}
                  className="w-full justify-start"
                >
                  <Eye className="h-4 w-4 mr-2" /> Preview only
                </Button>
              </div>
            </div>
          )}

          <div className="flex flex-col gap-2">
            <Button asChild variant="ghost" className="justify-start">
              <Link to="/dashboard">
                <FileText className="h-4 w-4 mr-2" /> Dashboard
              </Link>
            </Button>
            <Button asChild variant="ghost" className="justify-start">
              <Link to="/plugins">
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
            <Button onClick={onSignOut} variant="ghost" className="justify-start">
              <LogOut className="h-4 w-4 mr-2" /> Sign out
            </Button>
          </div>
        </div>
      </div>
    </>
  )
}
