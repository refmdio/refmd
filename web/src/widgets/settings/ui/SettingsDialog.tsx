/**
 * Settings Dialog
 *
 * Main settings dialog with tabs for different sections.
 */

import { useState } from 'react'
import {
  Dialog,
  DialogContent,
} from '@/shared/ui/dialog'
import { cn } from '@/shared/lib/utils'
import { Info, Shield, User } from 'lucide-react'
import { AboutSection } from './AboutSection'
import { SecuritySection } from './SecuritySection'
import { AccountSection } from './AccountSection'

type SettingsTab = 'about' | 'security' | 'account'

interface SettingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const tabs: { id: SettingsTab; label: string; icon: React.ReactNode }[] = [
  { id: 'about', label: 'About', icon: <Info className="h-4 w-4" /> },
  { id: 'security', label: 'Security', icon: <Shield className="h-4 w-4" /> },
  { id: 'account', label: 'Account', icon: <User className="h-4 w-4" /> },
]

export function SettingsDialog({ open, onOpenChange }: SettingsDialogProps) {
  const [activeTab, setActiveTab] = useState<SettingsTab>('about')

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl p-0 gap-0 h-[600px]">
        <div className="flex h-full min-h-0">
          {/* Sidebar */}
          <div className="w-48 border-r border-border/60 py-4 shrink-0 overflow-y-auto">
            <h2 className="px-4 mb-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Settings
            </h2>
            <nav className="space-y-1 px-2">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'w-full flex items-center gap-3 px-3 py-2 text-sm rounded transition-colors',
                    activeTab === tab.id
                      ? 'bg-foreground text-background'
                      : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
                  )}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>

          {/* Content */}
          <div className="flex-1 min-h-0 overflow-y-auto">
            {activeTab === 'about' && <AboutSection />}
            {activeTab === 'security' && <SecuritySection onClose={() => onOpenChange(false)} />}
            {activeTab === 'account' && <AccountSection onClose={() => onOpenChange(false)} />}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
