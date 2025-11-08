import type { KeyBinding, ShortcutAction } from '@/shared/types/shortcuts'

const chord = (
  key: string,
  modifiers?: { shift?: boolean; alt?: boolean; ctrl?: boolean; meta?: boolean },
): KeyBinding => [
  {
    key,
    shift: modifiers?.shift ?? false,
    alt: modifiers?.alt ?? false,
    ctrl: modifiers?.ctrl ?? false,
    meta: modifiers?.meta ?? false,
  },
]

export const SHORTCUT_ACTIONS: ShortcutAction[] = [
  {
    id: 'global.search.open',
    label: 'Quick search',
    description: 'Open the workspace search and command palette',
    category: 'Navigation',
    scope: 'global',
    default: {
      mac: [chord('k', { meta: true })],
      windows: [chord('k', { ctrl: true })],
    },
  },
  {
    id: 'global.settings.open',
    label: 'Open settings',
    description: 'Navigate to the keyboard shortcuts settings page',
    category: 'Navigation',
    scope: 'global',
    allowInInputs: true,
    default: {
      mac: [chord(',', { meta: true })],
      windows: [chord(',', { ctrl: true })],
    },
  },
  {
    id: 'global.profile.open',
    label: 'Open profile',
    description: 'Jump to your profile page',
    category: 'Navigation',
    scope: 'global',
    allowInInputs: true,
    default: {
      mac: [chord('p', { meta: true, shift: true })],
      windows: [chord('p', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'global.plugins.open',
    label: 'Open plugins',
    description: 'Manage installed plugins',
    category: 'Navigation',
    scope: 'global',
    allowInInputs: true,
    default: {
      mac: [chord('x', { meta: true, shift: true })],
      windows: [chord('x', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'global.document.new',
    label: 'Create new document',
    description: 'Create a regular workspace document',
    category: 'Workspace',
    scope: 'global',
    allowInInputs: true,
    default: {
      mac: [chord(';', { meta: true })],
      windows: [chord(';', { ctrl: true })],
    },
  },
  {
    id: 'global.temporary.open',
    label: 'Create temporary document',
    description: 'Start a local-only scratchpad',
    category: 'Workspace',
    scope: 'global',
    allowInInputs: true,
    default: {
      mac: [chord(';', { meta: true, shift: true })],
      windows: [chord(';', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'global.sidebar.toggle',
    label: 'Toggle sidebar',
    description: 'Collapse or expand the workspace sidebar',
    category: 'Workspace',
    scope: 'global',
    default: {
      mac: [chord('b', { meta: true })],
      windows: [chord('b', { ctrl: true })],
    },
  },
  {
    id: 'global.theme.toggle',
    label: 'Toggle theme',
    description: 'Switch between light and dark modes',
    category: 'Workspace',
    scope: 'global',
    allowInInputs: true,
    default: {
      mac: [chord('l', { meta: true, shift: true })],
      windows: [chord('l', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'view.mode.editor',
    label: 'Editor view',
    description: 'Switch to editor-only layout',
    category: 'View',
    scope: 'view',
    default: {
      mac: [chord('1', { meta: true })],
      windows: [chord('1', { ctrl: true })],
    },
  },
  {
    id: 'view.mode.split',
    label: 'Split view',
    description: 'Show editor and preview together',
    category: 'View',
    scope: 'view',
    default: {
      mac: [chord('2', { meta: true })],
      windows: [chord('2', { ctrl: true })],
    },
  },
  {
    id: 'view.mode.preview',
    label: 'Preview view',
    description: 'Switch to preview-only layout',
    category: 'View',
    scope: 'view',
    default: {
      mac: [chord('3', { meta: true })],
      windows: [chord('3', { ctrl: true })],
    },
  },
  {
    id: 'view.backlinks.toggle',
    label: 'Toggle backlinks',
    description: 'Open or close the backlink inspector',
    category: 'View',
    scope: 'view',
    default: {
      mac: [chord('b', { meta: true, shift: true })],
      windows: [chord('b', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'editor.sync-scroll.toggle',
    label: 'Toggle scroll sync',
    description: 'Lock or unlock preview scrolling with the editor',
    category: 'Editor',
    scope: 'editor',
    default: {
      mac: [chord('s', { meta: true, shift: true })],
      windows: [chord('s', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'editor.vim.toggle',
    label: 'Toggle Vim mode',
    description: 'Enable or disable Vim keybindings',
    category: 'Editor',
    scope: 'editor',
    default: {
      mac: [chord('v', { meta: true, shift: true })],
      windows: [chord('v', { ctrl: true, shift: true })],
    },
  },
  {
    id: 'editor.upload.trigger',
    label: 'Insert file…',
    description: 'Open the file picker to upload attachments',
    category: 'Editor',
    scope: 'editor',
    default: {
      mac: [chord('u', { meta: true, shift: true })],
      windows: [chord('u', { ctrl: true, shift: true })],
    },
  },
]

export const findShortcut = (id: string) => SHORTCUT_ACTIONS.find((action) => action.id === id)
