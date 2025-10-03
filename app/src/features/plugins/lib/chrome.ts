export type PluginChromeAction = {
  id?: string
  label: string
  onClick?: (event: MouseEvent) => void
  disabled?: boolean
  variant?: 'default' | 'primary' | 'ghost'
}

export type PluginChromeController = {
  setTitle: (title?: string | null) => void
  setStatus: (status?: string | null) => void
  setDocBadge: (value?: string | null) => void
  setActions: (actions: PluginChromeAction[]) => void
  reset: () => void
  destroy: () => void
  body: HTMLElement
}

export type PluginChromeApi = Pick<PluginChromeController, 'setTitle' | 'setStatus' | 'setDocBadge' | 'setActions' | 'reset'>

const BASE_BUTTON_CLASS = 'inline-flex items-center gap-1 rounded-md border px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-primary/40 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-60'
const VARIANT_CLASS: Record<Required<PluginChromeAction>['variant'], string> = {
  default: 'border-border/60 bg-background hover:bg-accent/60',
  primary: 'border-transparent bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm',
  ghost: 'border-transparent bg-transparent hover:bg-accent/60',
}

const HEADER_CLASS = 'refmd-plugin-shell__header flex flex-wrap items-center justify-between gap-3 border-b border-border/60 pb-3'
const TITLE_ROW_CLASS = 'refmd-plugin-shell__title-row flex items-center gap-2'
const TITLE_CLASS = 'refmd-plugin-shell__title text-base font-semibold text-foreground tracking-tight'
const BADGE_CLASS = 'refmd-plugin-shell__badge hidden rounded-full border border-border/50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.25em] text-muted-foreground'
const STATUS_CLASS = 'refmd-plugin-shell__status text-xs text-muted-foreground min-h-[1rem]'
const ACTIONS_CLASS = 'refmd-plugin-shell__actions flex flex-wrap items-center gap-2'
const ROOT_CLASS = 'refmd-plugin-shell flex h-full w-full flex-col gap-4'
const BODY_CLASS = 'refmd-plugin-shell__body flex-1 min-h-0'

export function createPluginChrome(container: HTMLElement): PluginChromeController {
  while (container.firstChild) {
    container.removeChild(container.firstChild)
  }

  const root = document.createElement('div')
  root.className = ROOT_CLASS

  const header = document.createElement('div')
  header.className = HEADER_CLASS

  const headerLeft = document.createElement('div')
  headerLeft.className = 'flex flex-col gap-1 min-w-0'

  const titleRow = document.createElement('div')
  titleRow.className = TITLE_ROW_CLASS

  const titleEl = document.createElement('span')
  titleEl.className = TITLE_CLASS
  titleEl.textContent = ''

  const badgeEl = document.createElement('span')
  badgeEl.className = BADGE_CLASS
  badgeEl.textContent = ''

  const statusEl = document.createElement('span')
  statusEl.className = STATUS_CLASS
  statusEl.textContent = ''

  const actionsEl = document.createElement('div')
  actionsEl.className = ACTIONS_CLASS
  actionsEl.setAttribute('data-actions-count', '0')

  titleRow.append(titleEl, badgeEl)
  headerLeft.append(titleRow, statusEl)
  header.append(headerLeft, actionsEl)

  const body = document.createElement('div')
  body.className = BODY_CLASS

  root.append(header, body)
  container.append(root)

  let actionCleanup: Array<() => void> = []

  const clearActions = () => {
    for (const cleanup of actionCleanup) {
      try {
        cleanup()
      } catch {
        /* noop */
      }
    }
    actionCleanup = []
    while (actionsEl.firstChild) {
      actionsEl.removeChild(actionsEl.firstChild)
    }
    actionsEl.setAttribute('data-actions-count', '0')
    actionsEl.classList.add('hidden')
  }

  const controller: PluginChromeController = {
    setTitle: (title?: string | null) => {
      titleEl.textContent = title ? String(title) : ''
    },
    setStatus: (status?: string | null) => {
      statusEl.textContent = status ? String(status) : ''
    },
    setDocBadge: (value?: string | null) => {
      if (value && value.trim()) {
        badgeEl.textContent = value
        badgeEl.classList.remove('hidden')
      } else {
        badgeEl.textContent = ''
        badgeEl.classList.add('hidden')
      }
    },
    setActions: (actions: PluginChromeAction[]) => {
      clearActions()
      const list = Array.isArray(actions) ? actions : []
      if (!list.length) return
      for (const action of list) {
        const btn = document.createElement('button')
        const variant = action.variant ?? 'default'
        btn.className = `${BASE_BUTTON_CLASS} ${VARIANT_CLASS[variant]}`
        const label = typeof action.label === 'string' ? action.label : ''
        btn.textContent = label
        if (action.disabled) btn.disabled = true
        if (typeof action.id === 'string') {
          btn.dataset.actionId = action.id
        }
        if (typeof action.onClick === 'function') {
          const handler = (event: MouseEvent) => {
            try {
              action.onClick?.(event)
            } catch (err) {
              console.error('[plugin chrome] action handler failed', err)
            }
          }
          btn.addEventListener('click', handler)
          actionCleanup.push(() => btn.removeEventListener('click', handler))
        }
        actionsEl.append(btn)
      }
      actionsEl.setAttribute('data-actions-count', String(list.length))
      actionsEl.classList.remove('hidden')
    },
    reset: () => {
      controller.setTitle('')
      controller.setStatus('')
      controller.setDocBadge('')
      clearActions()
    },
    destroy: () => {
      controller.reset()
      try {
        container.removeChild(root)
      } catch {
        /* noop */
      }
    },
    get body() {
      return body
    },
  }

  // hide actions initially
  actionsEl.classList.add('hidden')

  return controller
}
