/**
 * Client-side WASM Runtime
 *
 * Executes plugin WASM modules in the browser using Extism JS SDK.
 * This replaces server-side WASM execution for E2EE compatibility.
 */

import { createPlugin, type Plugin } from '@extism/extism'

/** Plugin execution context */
export interface ExecContext {
  docId: string | null
  userId: string | null
}

/** Plugin execution output */
export interface ExecOutput {
  ok: boolean
  data: unknown
  effects: Effect[]
  error: { code: string; message: string } | null
}

/** Effect types that plugins can emit */
export interface Effect {
  type: string
  [key: string]: unknown
}

/**
 * Client-side WASM runtime for plugin execution.
 *
 * Manages plugin lifecycle and execution in the browser.
 */
export class ClientWasmRuntime {
  private plugins: Map<string, Plugin> = new Map()
  private loadingPromises: Map<string, Promise<void>> = new Map()

  /**
   * Load a plugin WASM module.
   *
   * @param pluginId - Unique plugin identifier
   * @param wasmUrl - URL to fetch WASM module from
   */
  async loadPlugin(pluginId: string, wasmUrl: string): Promise<void> {
    // Return existing loading promise if already loading
    const existing = this.loadingPromises.get(pluginId)
    if (existing) {
      return existing
    }

    // Return immediately if already loaded
    if (this.plugins.has(pluginId)) {
      return
    }

    const loadPromise = (async () => {
      try {
        const response = await fetch(wasmUrl)
        if (!response.ok) {
          throw new Error(`Failed to fetch WASM: ${response.status} ${response.statusText}`)
        }

        const wasmBytes = await response.arrayBuffer()

        // Extism requires a manifest with wasm key
        const manifest = {
          wasm: [{ data: new Uint8Array(wasmBytes) }],
        }

        const plugin = await createPlugin(manifest, {
          useWasi: true,
          // runInWorker requires crossOriginIsolated which needs COOP/COEP headers
          runInWorker: false,
        })

        this.plugins.set(pluginId, plugin)
      } finally {
        this.loadingPromises.delete(pluginId)
      }
    })()

    this.loadingPromises.set(pluginId, loadPromise)
    return loadPromise
  }

  /**
   * Check if a plugin is loaded.
   */
  isLoaded(pluginId: string): boolean {
    return this.plugins.has(pluginId)
  }

  /**
   * Execute a plugin action.
   *
   * @param pluginId - Plugin to execute
   * @param action - Action name
   * @param payload - Action payload
   * @param ctx - Execution context
   * @returns Execution result with effects
   */
  async execute(
    pluginId: string,
    action: string,
    payload: unknown,
    ctx: ExecContext
  ): Promise<ExecOutput> {
    const plugin = this.plugins.get(pluginId)
    if (!plugin) {
      return {
        ok: false,
        data: null,
        effects: [],
        error: { code: 'PLUGIN_NOT_LOADED', message: `Plugin ${pluginId} is not loaded` },
      }
    }

    try {
      const input = JSON.stringify({
        action,
        payload: payload ?? {},
        ctx: {
          doc_id: ctx.docId,
          user_id: ctx.userId,
        },
      })

      const output = await plugin.call('exec', input)
      if (!output) {
        return {
          ok: false,
          data: null,
          effects: [],
          error: { code: 'WASM_NO_OUTPUT', message: 'Plugin returned no output' },
        }
      }
      const result = output.json()

      return {
        ok: result.ok ?? true,
        data: result.data ?? null,
        effects: result.effects ?? [],
        error: result.error ?? null,
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      return {
        ok: false,
        data: null,
        effects: [],
        error: { code: 'WASM_EXECUTION_ERROR', message },
      }
    }
  }

  /**
   * Unload a plugin and free resources.
   */
  async unload(pluginId: string): Promise<void> {
    const plugin = this.plugins.get(pluginId)
    if (plugin) {
      try {
        await plugin.close()
      } catch {
        // Ignore close errors
      }
      this.plugins.delete(pluginId)
    }
  }

  /**
   * Unload all plugins.
   */
  async unloadAll(): Promise<void> {
    const pluginIds = Array.from(this.plugins.keys())
    await Promise.all(pluginIds.map((id) => this.unload(id)))
  }
}

/** Singleton instance for shared use */
let sharedRuntime: ClientWasmRuntime | null = null

/**
 * Get the shared WASM runtime instance.
 */
export function getWasmRuntime(): ClientWasmRuntime {
  if (!sharedRuntime) {
    sharedRuntime = new ClientWasmRuntime()
  }
  return sharedRuntime
}
