/**
 * WebSocket Sync Client
 *
 * State machine: idle → connecting → connected → disconnected → connecting (retry)
 *                                                             → failed (max retries)
 *
 * Three queues:
 * - incoming: server messages to process
 * - custom: locally generated messages waiting to send
 * - pending: sent messages waiting for confirmation (update-saved / snapshot-saved)
 */

import { API_BASE } from '@/shared/api/core'
import {
  VerificationError,
} from './types'
import type {
  QueuedMessage,
  WsConnectionState,
  WsServerMessage,
  WsSyncCallbacks,
} from './types'

/** Max reconnection attempts */
const MAX_RETRIES = 13
/** Base delay for exponential backoff (ms) */
const BASE_DELAY_MS = 100
/** Backoff multiplier */
const BACKOFF_MULTIPLIER = 1.8
/** Max delay cap (ms) */
const MAX_DELAY_MS = 30_000

export class DocumentWebSocket {
  private ws: WebSocket | null = null
  private state: WsConnectionState = 'idle'
  private retryCount = 0
  private retryTimeout: ReturnType<typeof setTimeout> | null = null

  /** Messages waiting to be sent */
  private sendQueue: QueuedMessage[] = []
  /** Messages sent, waiting for server confirmation */
  private pendingQueue: QueuedMessage[] = []

  /** Incoming messages waiting to be processed (serial queue) */
  private incomingQueue: string[] = []
  /** True while an incoming message is being processed */
  private processing = false

  private readonly documentId: string
  private callbacks: WsSyncCallbacks

  /** Subscriber callbacks for broadcast (onStateChange, onError) */
  private stateChangeSubscribers = new Set<(state: WsConnectionState) => void>()
  private errorSubscribers = new Set<(error: string) => void>()

  /** Known snapshot + clocks for delta reconnection */
  private knownSnapshotId: string | null = null
  private knownSnapshotUpdateClocks: Record<string, number> = {}

  /** When true, force complete mode on next reconnect (delta failed) */
  private forceCompleteMode = false

  /** True until the first 'document' message is received after connect/reconnect */
  private waitingForInitialState = false

  /** Connection mode used for the current WebSocket session */
  private currentMode: 'complete' | 'delta' = 'complete'

  constructor(documentId: string, callbacks: WsSyncCallbacks) {
    this.documentId = documentId
    this.callbacks = callbacks
  }

  /** Connect to the WebSocket endpoint */
  connect(mode: 'complete' | 'delta' = 'complete'): void {
    if (this.state === 'connecting' || this.state === 'connected') return

    this.setState('connecting')
    this.waitingForInitialState = true
    this.currentMode = mode

    // Derive WS URL from API_BASE (e.g. http://localhost:8000 → ws://localhost:8000)
    const apiUrl = new URL(API_BASE)
    const wsProtocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:'
    const params = new URLSearchParams()
    params.set('mode', mode)

    if (this.knownSnapshotId) {
      params.set('knownSnapshotId', this.knownSnapshotId)
    }
    if (mode === 'delta') {
      params.set(
        'knownSnapshotUpdateClocks',
        JSON.stringify(this.knownSnapshotUpdateClocks)
      )
    }

    const url = `${wsProtocol}//${apiUrl.host}/api/documents/${this.documentId}/ws?${params.toString()}`
    this.ws = new WebSocket(url)

    this.ws.onopen = () => {
      this.setState('connected')
      this.retryCount = 0
      this.forceCompleteMode = false
      // Move unacknowledged pending messages back to send queue for resend
      if (this.pendingQueue.length > 0) {
        this.sendQueue.unshift(...this.pendingQueue)
        this.pendingQueue = []
      }
      // Do NOT flush here — wait for the initial 'document' message first
    }

    this.ws.onmessage = (event) => {
      this.incomingQueue.push(event.data as string)
      this.processIncomingQueue().catch((err) => {
        console.error('[ws] Unhandled error in message processing:', err)
        this.broadcastError('unrecoverable-error')
        this.disconnect()
      })
    }

    this.ws.onclose = () => {
      this.ws = null
      if (this.state === 'connected' || this.state === 'connecting') {
        // Force complete mode on next reconnect when:
        // 1. WS was never opened (still 'connecting') — server rejected the upgrade
        //    (e.g. 404 for stale knownSnapshotId)
        // 2. Disconnected before receiving the initial 'document' message
        //    (waitingForInitialState is true) — client has no verified state from
        //    this session, so delta would be ambiguous (fail-closed reconnect,
        //    see collaboration.md).
        // In both cases, KEEP knownSnapshotId for anti-rollback proof chain.
        if (this.state === 'connecting' || this.waitingForInitialState) {
          this.forceCompleteMode = true
        }
        this.setState('disconnected')
        this.scheduleReconnect()
      }
    }

    this.ws.onerror = () => {
      // onclose will fire after onerror
    }
  }

  /** Disconnect and stop retrying */
  disconnect(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout)
      this.retryTimeout = null
    }
    if (this.ws) {
      this.ws.onclose = null
      this.ws.close()
      this.ws = null
    }
    this.incomingQueue = []
    this.processing = false
    this.setState('idle')
  }

  /** Send a message through the WebSocket */
  send(message: QueuedMessage): void {
    if (this.state === 'connected' && this.ws?.readyState === WebSocket.OPEN && !this.waitingForInitialState) {
      this.ws.send(JSON.stringify(message.envelope))
      if (message.type !== 'ephemeral') {
        this.pendingQueue.push(message)
      }
    } else {
      // Drop ephemeral messages in failed state to prevent unbounded queue growth
      if (this.state === 'failed' && message.type === 'ephemeral') return
      this.sendQueue.push(message)
    }
  }

  /** Update known state for delta reconnection */
  updateKnownState(
    snapshotId: string | null,
    clocks: Record<string, number>,
  ): void {
    this.knownSnapshotId = snapshotId
    this.knownSnapshotUpdateClocks = { ...clocks }
  }

  /** Get current connection state */
  getState(): WsConnectionState {
    return this.state
  }

  /** Subscribe additional UI callbacks (for shared WS reuse by multiple panels).
   *  Returns an unsubscribe function for cleanup. */
  subscribe(handlers: { onStateChange: (s: WsConnectionState) => void; onError: (e: string) => void }): () => void {
    this.stateChangeSubscribers.add(handlers.onStateChange)
    this.errorSubscribers.add(handlers.onError)
    return () => {
      this.stateChangeSubscribers.delete(handlers.onStateChange)
      this.errorSubscribers.delete(handlers.onError)
    }
  }

  /** Resolve a pending message by clock + snapshotId (update-saved) */
  resolvePending(clock: number, snapshotId?: string): QueuedMessage | undefined {
    const idx = this.pendingQueue.findIndex(
      (m) => m.type === 'update' && m.clock === clock && (!snapshotId || m.refSnapshotId === snapshotId)
    )
    if (idx !== -1) {
      return this.pendingQueue.splice(idx, 1)[0]
    }
    return undefined
  }

  /** Remove queued ephemeral messages (stale after session rotation) */
  drainEphemeralQueue(): void {
    this.sendQueue = this.sendQueue.filter((m) => m.type !== 'ephemeral')
  }

  /** Drain all pending and queued messages (for full state reset before reconnect) */
  drainAllQueues(): QueuedMessage[] {
    const all = [...this.pendingQueue, ...this.sendQueue]
    this.pendingQueue = []
    this.sendQueue = []
    return all
  }

  /** Resolve a pending snapshot message (snapshot-saved) */
  resolvePendingSnapshot(): QueuedMessage | undefined {
    const idx = this.pendingQueue.findIndex((m) => m.type === 'snapshot')
    if (idx !== -1) {
      return this.pendingQueue.splice(idx, 1)[0]
    }
    return undefined
  }

  private setState(newState: WsConnectionState): void {
    this.state = newState
    for (const cb of this.stateChangeSubscribers) cb(newState)
  }

  private broadcastError(error: string): void {
    for (const cb of this.errorSubscribers) cb(error)
  }

  private async processIncomingQueue(): Promise<void> {
    if (this.processing) return
    this.processing = true
    try {
      while (this.incomingQueue.length > 0) {
        const data = this.incomingQueue.shift()!
        await this.handleMessage(data)
      }
    } finally {
      this.processing = false
    }
  }

  private async handleMessage(data: string): Promise<void> {
    let msg: WsServerMessage
    try {
      msg = JSON.parse(data) as WsServerMessage
    } catch {
      return
    }

    switch (msg.type) {
      case 'document':
        try {
          await this.callbacks.onDocument(msg, this.currentMode)
          this.waitingForInitialState = false
          this.flushSendQueue()
        } catch (err) {
          if (err instanceof VerificationError) {
            console.error('[ws] Verification failed on document message, disconnecting:', err.message)
            this.broadcastError('verification-failed')
            this.disconnect()
          } else {
            // Transient error (e.g. network failure during device-key bootstrap):
            // close WS to trigger onclose → scheduleReconnect instead of permanent disconnect
            console.warn('[ws] Transient error on document message, will reconnect:', err)
            this.ws?.close()
          }
          return
        }
        break
      case 'update':
        try {
          await this.callbacks.onUpdate(msg)
        } catch (err) {
          if (err instanceof VerificationError) {
            console.error('[ws] Verification failed on update message, disconnecting:', err.message)
            this.broadcastError('verification-failed')
          } else {
            console.error('[ws] Unrecoverable error on update message, disconnecting:', err)
            this.broadcastError('unrecoverable-error')
          }
          this.disconnect()
          return
        }
        break
      case 'snapshot':
        try {
          await this.callbacks.onSnapshot(msg)
        } catch (err) {
          if (err instanceof VerificationError) {
            console.error('[ws] Verification failed on snapshot message, disconnecting:', err.message)
            this.broadcastError('verification-failed')
          } else {
            console.error('[ws] Unrecoverable error on snapshot message, disconnecting:', err)
            this.broadcastError('unrecoverable-error')
          }
          this.disconnect()
          return
        }
        break
      case 'update-saved':
        this.callbacks.onUpdateSaved(msg)
        break
      case 'update-save-failed':
        this.callbacks.onUpdateSaveFailed(msg)
        break
      case 'snapshot-saved':
        this.callbacks.onSnapshotSaved(msg)
        break
      case 'snapshot-save-failed':
        try {
          await this.callbacks.onSnapshotSaveFailed(msg)
        } catch (err) {
          if (err instanceof VerificationError) {
            console.error('[ws] Verification failed on snapshot-save-failed message, disconnecting:', err.message)
            this.broadcastError('verification-failed')
          } else {
            console.error('[ws] Unrecoverable error on snapshot-save-failed message, disconnecting:', err)
            this.broadcastError('unrecoverable-error')
          }
          this.disconnect()
          return
        }
        break
      case 'ephemeral-message':
        try {
          await this.callbacks.onEphemeral(msg)
        } catch (err) {
          if (err instanceof VerificationError) {
            console.error('[ws] Verification failed on ephemeral message, disconnecting:', err.message)
            this.broadcastError('verification-failed')
            this.disconnect()
            return
          }
          // Other ephemeral errors are non-fatal (awareness/handshake): log and continue
          console.warn('[ws] Error processing ephemeral message:', err)
        }
        break
      case 'document-not-found':
        this.broadcastError('document-not-found')
        this.disconnect()
        break
      case 'unauthorized':
        this.broadcastError('unauthorized')
        this.disconnect()
        break
      case 'document-error':
        this.broadcastError('document-error')
        break
      case 'validation-error':
        this.broadcastError(`validation-error: [${msg.messageType}] ${msg.detail}`)
        break
    }
  }

  private scheduleReconnect(): void {
    if (this.retryCount >= MAX_RETRIES) {
      this.setState('failed')
      return
    }

    const delay = Math.min(BASE_DELAY_MS * Math.pow(BACKOFF_MULTIPLIER, this.retryCount), MAX_DELAY_MS)
    this.retryCount++

    this.retryTimeout = setTimeout(() => {
      this.retryTimeout = null
      // On reconnect, use delta mode if we have known state and delta wasn't rejected
      let mode: 'complete' | 'delta' = 'complete'
      if (this.knownSnapshotId && !this.forceCompleteMode) {
        mode = 'delta'
      }
      this.forceCompleteMode = false
      this.connect(mode)
    }, delay)
  }

  private flushSendQueue(): void {
    while (
      this.sendQueue.length > 0 &&
      this.ws?.readyState === WebSocket.OPEN
    ) {
      const msg = this.sendQueue.shift()!
      this.ws.send(JSON.stringify(msg.envelope))
      if (msg.type !== 'ephemeral') {
        this.pendingQueue.push(msg)
      }
    }
  }
}
