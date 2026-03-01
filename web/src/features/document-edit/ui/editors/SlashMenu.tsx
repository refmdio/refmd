/**
 * Slash Menu Component
 *
 * Notion-style slash command popup with category tabs, icons,
 * and keyboard navigation. Uses omni-ui styling.
 *
 * Purely presentational — command execution is handled via onSelect callback.
 */

import { useEffect, useRef, useState, useMemo } from 'react'
import { createPortal } from 'react-dom'
import type { EditorView } from 'prosemirror-view'
import { computePosition, offset, flip, shift } from '@floating-ui/dom'
import {
  Type,
  Heading1,
  Heading2,
  Heading3,
  List,
  ListOrdered,
  Quote,
  Code,
  Minus,
} from 'lucide-react'
import {
  CATEGORY_LABELS,
  CATEGORY_ORDER,
  type SlashCommand,
  type SlashMenuState,
  type SlashCommandCategory,
} from '../../lib/prosemirror/slash-commands'

const ICON_MAP: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  'type': Type,
  'heading-1': Heading1,
  'heading-2': Heading2,
  'heading-3': Heading3,
  'list': List,
  'list-ordered': ListOrdered,
  'quote': Quote,
  'code': Code,
  'minus': Minus,
}

interface SlashMenuProps {
  view: EditorView
  slashState: SlashMenuState
  onSelect: (cmd: SlashCommand) => void
}

/** Group commands by category, preserving CATEGORY_ORDER */
function groupByCategory(commands: SlashCommand[]) {
  const groups: { category: SlashCommandCategory; label: string; items: SlashCommand[] }[] = []
  const map = new Map<SlashCommandCategory, SlashCommand[]>()

  for (const cmd of commands) {
    let arr = map.get(cmd.category)
    if (!arr) {
      arr = []
      map.set(cmd.category, arr)
    }
    arr.push(cmd)
  }

  for (const cat of CATEGORY_ORDER) {
    const items = map.get(cat)
    if (items && items.length > 0) {
      groups.push({ category: cat, label: CATEGORY_LABELS[cat], items })
    }
  }

  return groups
}

export function SlashMenu({ view, slashState, onSelect }: SlashMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null)
  const selectedRef = useRef<HTMLButtonElement>(null)
  const [activeTab, setActiveTab] = useState<SlashCommandCategory | 'all'>('all')

  // Reset tab when menu opens or query changes
  useEffect(() => {
    setActiveTab('all')
  }, [slashState.active])

  // Filtered commands based on active tab
  const displayCommands = useMemo(() => {
    if (activeTab === 'all') return slashState.commands
    return slashState.commands.filter((c) => c.category === activeTab)
  }, [slashState.commands, activeTab])

  const groups = useMemo(() => groupByCategory(displayCommands), [displayCommands])

  // Available tabs: only show categories that have matching commands
  const availableTabs = useMemo(() => {
    const cats = new Set(slashState.commands.map((c) => c.category))
    return CATEGORY_ORDER.filter((c) => cats.has(c))
  }, [slashState.commands])

  // Position the menu
  useEffect(() => {
    const menu = menuRef.current
    if (!menu) return

    const virtualEl = {
      getBoundingClientRect: () => {
        const coords = view.coordsAtPos(slashState.pos)
        return new DOMRect(coords.left, coords.bottom, 0, 0)
      },
    }

    computePosition(virtualEl, menu, {
      placement: 'bottom-start',
      middleware: [offset(4), flip(), shift({ padding: 8 })],
    }).then(({ x, y }) => {
      menu.style.left = `${x}px`
      menu.style.top = `${y}px`
    })
  }, [view, slashState])

  // Scroll selected into view
  useEffect(() => {
    selectedRef.current?.scrollIntoView({ block: 'nearest' })
  }, [slashState.selectedIndex])

  if (slashState.commands.length === 0) return null

  // Resolve which command is selected in the potentially tab-filtered view
  const selectedCommand = slashState.commands[slashState.selectedIndex]

  // Whether we're in search mode (query typed)
  const isSearching = slashState.query.length > 0

  return createPortal(
    <div
      ref={menuRef}
      className="fixed z-50 flex w-72 max-h-80 flex-col overflow-hidden border border-border/60 bg-muted/60 text-foreground shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]"
    >
      {/* Category tabs — hidden during search */}
      {!isSearching && availableTabs.length > 1 && (
        <div className="flex shrink-0 gap-0 border-b border-border/40 px-1 pt-1">
          <TabButton
            active={activeTab === 'all'}
            onClick={() => setActiveTab('all')}
          >
            All
          </TabButton>
          {availableTabs.map((cat) => (
            <TabButton
              key={cat}
              active={activeTab === cat}
              onClick={() => setActiveTab(cat)}
            >
              {CATEGORY_LABELS[cat]}
            </TabButton>
          ))}
        </div>
      )}

      {/* Command list */}
      <div className="min-h-0 flex-1 overflow-y-auto p-1">
          {groups.map((group) => (
            <div key={group.category}>
              {/* Category header — only show in "all" tab and not searching */}
              {activeTab === 'all' && !isSearching && groups.length > 1 && (
                <div className="px-2 pb-1 pt-2 font-mono text-[10px] uppercase tracking-[0.3em] text-muted-foreground/60">
                  {group.label}
                </div>
              )}
              {group.items.map((cmd) => {
                const isSelected = selectedCommand === cmd
                const IconComp = ICON_MAP[cmd.icon]

                return (
                  <button
                    key={cmd.shortcut}
                    ref={isSelected ? selectedRef : undefined}
                    type="button"
                    className={`flex w-full items-center gap-3 px-2 py-1.5 text-left transition-colors ${
                      isSelected
                        ? 'bg-foreground text-background'
                        : 'hover:bg-muted'
                    }`}
                    onMouseDown={(e) => {
                      e.preventDefault()
                      onSelect(cmd)
                    }}
                  >
                    <span
                      className={`flex size-8 shrink-0 items-center justify-center border ${
                        isSelected
                          ? 'border-background/30 bg-background/10'
                          : 'border-border/60 bg-background/50'
                      }`}
                    >
                      {IconComp && (
                        <IconComp
                          size={16}
                          className={isSelected ? 'text-background' : 'text-muted-foreground'}
                        />
                      )}
                    </span>
                    <div className="flex min-w-0 flex-col">
                      <span className="text-sm font-medium leading-tight">
                        {cmd.label}
                      </span>
                      <span
                        className={`text-[11px] leading-tight ${
                          isSelected
                            ? 'text-background/60'
                            : 'text-muted-foreground'
                        }`}
                      >
                        {cmd.description}
                      </span>
                    </div>
                  </button>
                )
              })}
            </div>
          ))}
      </div>
    </div>,
    document.body
  )
}

/** Tab button for category switching */
function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      className={`px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-[0.2em] transition-colors ${
        active
          ? 'border-b border-foreground text-foreground'
          : 'text-muted-foreground hover:text-foreground'
      }`}
      onMouseDown={(e) => {
        e.preventDefault()
        onClick()
      }}
    >
      {children}
    </button>
  )
}
