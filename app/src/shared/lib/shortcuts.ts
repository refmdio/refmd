import isHotkey from 'is-hotkey'

import type {
  KeyBinding,
  KeyChord,
  ShortcutAction,
  ShortcutAssignment,
  ShortcutAssignmentMap,
  ShortcutMode,
} from '@/shared/types/shortcuts'

export type ShortcutPlatform = 'mac' | 'windows'

export const detectPlatform = (): ShortcutPlatform => {
  if (typeof navigator === 'undefined') return 'windows'
  const platform = navigator.platform || navigator.userAgent
  return /Mac|iPhone|iPad|iPod/i.test(platform) ? 'mac' : 'windows'
}

const normalizeKey = (value: string) => (value.length === 1 ? value.toLowerCase() : value)

const normalizeHotkeyKey = (value: string) => value.toLowerCase()

const cloneChord = (chord: KeyChord): KeyChord => ({
  key: normalizeKey(chord.key),
  shift: Boolean(chord.shift),
  alt: Boolean(chord.alt),
  ctrl: Boolean(chord.ctrl),
  meta: Boolean(chord.meta),
})

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const isValidChord = (value: unknown): value is KeyChord => {
  if (!isPlainObject(value)) return false
  if (typeof value.key !== 'string' || value.key.length === 0) return false
  return true
}

const isValidBinding = (value: unknown): value is KeyBinding => {
  if (!Array.isArray(value) || value.length === 0) return false
  return value.every(isValidChord)
}

const isValidBindingList = (value: unknown): value is KeyBinding[] => {
  if (!Array.isArray(value)) return false
  return value.every(isValidBinding)
}

export const chordFromEvent = (event: KeyboardEvent): KeyChord | null => {
  const key = event.key
  if (!key) return null
  const disallowed = ['Meta', 'Control', 'Shift', 'Alt']
  if (disallowed.includes(key)) return null
  return {
    key: normalizeKey(key),
    shift: event.shiftKey,
    alt: event.altKey,
    ctrl: event.ctrlKey,
    meta: event.metaKey,
  }
}

export const normalizeAssignments = (source: unknown): ShortcutAssignmentMap => {
  if (!isPlainObject(source)) return {}
  const result: ShortcutAssignmentMap = {}
  for (const [actionId, modes] of Object.entries(source)) {
    if (!isPlainObject(modes)) continue
    const normalized: ShortcutAssignment = {}
    for (const [mode, bindings] of Object.entries(modes)) {
      if (!isValidBindingList(bindings)) continue
      const cloned = bindings.map((binding) => binding.map(cloneChord))
      if (cloned.length > 0) {
        normalized[mode as ShortcutMode] = cloned
      }
    }
    if (Object.keys(normalized).length > 0) {
      result[actionId] = normalized
    }
  }
  return result
}

export const serializeAssignments = (assignments: ShortcutAssignmentMap) => {
  const payload: Record<string, unknown> = {}
  for (const [actionId, modes] of Object.entries(assignments)) {
    const entry: Record<string, unknown> = {}
    for (const [mode, bindings] of Object.entries(modes)) {
      if (!bindings || bindings.length === 0) continue
      entry[mode] = bindings.map((binding) =>
        binding.map((chord) => ({
          key: chord.key,
          shift: Boolean(chord.shift),
          alt: Boolean(chord.alt),
          ctrl: Boolean(chord.ctrl),
          meta: Boolean(chord.meta),
        })),
      )
    }
    if (Object.keys(entry).length > 0) {
      payload[actionId] = entry
    }
  }
  return payload
}

export const resolveBindings = (
  action: ShortcutAction,
  assignments: ShortcutAssignmentMap,
  platform: ShortcutPlatform,
  mode: ShortcutMode = 'default',
): KeyBinding[] => {
  const userBindings = assignments[action.id]?.[mode]
  if (userBindings && userBindings.length > 0) {
    return userBindings.map((binding) => binding.map(cloneChord))
  }
  const platformDefaults = platform === 'mac' ? action.default.mac : action.default.windows
  const fallback = platformDefaults ?? action.default.mac ?? action.default.windows ?? []
  return fallback.map((binding) => binding.map(cloneChord))
}

const createHotkeyString = (chord: KeyChord, useModAlias: boolean) => {
  const parts: string[] = []
  const useMod = useModAlias && (chord.meta || chord.ctrl)
  if (useMod) {
    parts.push('mod')
  } else {
    if (chord.meta) parts.push('meta')
    if (chord.ctrl) parts.push('ctrl')
  }
  if (chord.alt) parts.push('alt')
  if (chord.shift) parts.push('shift')
  parts.push(normalizeHotkeyKey(chord.key))
  return parts.join('+')
}

const chordToHotkeys = (chord: KeyChord) => {
  const hotkeys = new Set<string>()
  hotkeys.add(createHotkeyString(chord, false))
  if ((chord.meta || chord.ctrl) && !(chord.meta && chord.ctrl)) {
    hotkeys.add(createHotkeyString(chord, true))
  }
  return Array.from(hotkeys)
}

export const matchBinding = (binding: KeyBinding, event: KeyboardEvent) => {
  if (binding.length !== 1) return false
  const chord = binding[0]
  return chordToHotkeys(chord).some((hotkey) => isHotkey(hotkey, { byKey: true }, event))
}

const SYMBOLS: Record<ShortcutPlatform, Record<'meta' | 'ctrl' | 'alt' | 'shift', string>> = {
  mac: { meta: '⌘', ctrl: '⌃', alt: '⌥', shift: '⇧' },
  windows: { meta: 'Win', ctrl: 'Ctrl', alt: 'Alt', shift: 'Shift' },
}

export const formatBinding = (binding: KeyBinding, platform: ShortcutPlatform) => {
  if (binding.length === 0) return ''
  const chord = binding[0]
  const symbols = SYMBOLS[platform]
  const parts: string[] = []
  if (chord.meta) parts.push(symbols.meta)
  if (chord.ctrl) parts.push(symbols.ctrl)
  if (chord.alt) parts.push(symbols.alt)
  if (chord.shift) parts.push(symbols.shift)
  const label = chord.key.length === 1 ? chord.key.toUpperCase() : chord.key
  parts.push(label)
  return parts.join(' + ')
}

export const isTextInputEvent = (event: KeyboardEvent) => {
  const target = event.target as HTMLElement | null
  if (!target) return false
  const tagName = target.tagName.toLowerCase()
  if (tagName === 'input' || tagName === 'textarea') return true
  if (target.isContentEditable) return true
  return false
}
