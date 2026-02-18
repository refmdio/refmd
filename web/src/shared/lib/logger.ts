/**
 * Structured Logger
 *
 * Centralized logging with consistent format and level control.
 * Replaces scattered console.warn/error calls across crypto and device modules.
 *
 * Production: Only 'error' level is shown.
 * Development: All levels are shown.
 */

export type LogLevel = 'warn' | 'error'

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  warn: 0,
  error: 1,
}

const MIN_LEVEL: LogLevel = import.meta.env.PROD ? 'error' : 'warn'

const LOG_METHODS: Record<LogLevel, (...args: unknown[]) => void> = {
  warn: console.warn,
  error: console.error,
}

function log(level: LogLevel, tag: string, message: string, detail?: unknown): void {
  if (LEVEL_PRIORITY[level] < LEVEL_PRIORITY[MIN_LEVEL]) return

  const method = LOG_METHODS[level]
  if (detail !== undefined) {
    method(`[${tag}] ${message}`, detail)
  } else {
    method(`[${tag}] ${message}`)
  }
}

export const logger = {
  warn: (tag: string, message: string, detail?: unknown) => log('warn', tag, message, detail),
  error: (tag: string, message: string, detail?: unknown) => log('error', tag, message, detail),
}
