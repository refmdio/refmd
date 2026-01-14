/**
 * E2EE Realtime Sync
 *
 * Secure synchronization state machine for Yjs documents.
 * Replaces y-websocket with E2EE-enabled communication.
 */

import type * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import {
  createUpdate,
  createSnapshot,
  verifyAndDecryptUpdate,
  verifyAndDecryptSnapshot,
  decryptInitSnapshot,
  decryptSyncUpdate,
  isServerInitMessage,
  isServerSyncUpdate,
  isRealtimeMessage,
  type ServerMessage,
  type ServerInitMessage,
  type UpdatePublicData,
  type SnapshotPublicData,
} from './messages'
import {
  createEphemeralSession,
  createEphemeralMessage,
  createInitializeMessage,
  verifyAndDecryptEphemeralMessage,
  generateSessionId,
  type EphemeralSession,
  type EphemeralMessage,
  type EphemeralPublicData as EphemeralPublicDataFromEphemeral,
} from './ephemeral'
import {
  getKeyManager,
  SessionLockedError,
  getSodium,
  fromBase64,
} from '@/features/e2ee'
import { getMyWorkspaceKey, getDocumentKey } from '@/shared/api/client'

// ============================================
// Types
// ============================================

/** Sync status */
export type SyncStatus = 'disconnected' | 'connecting' | 'syncing' | 'ready' | 'error'

/** Sync state */
export interface SyncState {
  status: SyncStatus
  lastSeq: number
  localClock: number
  currentSnapshotId: string | null
  updateClocks: Map<string, number>
  error: string | null
}

/** Status event payload (compatible with y-websocket) */
export interface StatusEvent {
  status: 'connecting' | 'connected' | 'disconnected'
}

/** Status event handler */
export type StatusEventHandler = (event: StatusEvent) => void

/** Options for creating a secure connection */
export interface SecureConnectionOptions {
  token?: string | null
  connect?: boolean
  workspaceId: string
  /** Callback to fetch encrypted KEK from API */
  fetchKek?: () => Promise<string>
  /** Callback to fetch encrypted DEK from API */
  fetchDek?: () => Promise<{ encryptedDek: string; nonce: string }>
}

/** Secure connection interface (compatible with WebsocketProvider API) */
export interface SecureConnection {
  awareness: Awareness
  readonly connected: boolean
  readonly syncState: SyncState
  /** Whether the connection should automatically connect */
  shouldConnect: boolean
  connect(): void
  disconnect(): void
  destroy(): void
  /** Listen to status events */
  on(event: 'status', handler: StatusEventHandler): void
  /** Stop listening to status events */
  off(event: 'status', handler: StatusEventHandler): void
}

// ============================================
// Constants
// ============================================

/** Number of updates before creating a new snapshot */
const SNAPSHOT_THRESHOLD = 100

/** Debounce delay for tag updates in milliseconds (auto-save style) */
const TAG_UPDATE_DEBOUNCE_MS = 2000

/** Reconnect delay in milliseconds */
const RECONNECT_DELAY = 1000

/** Max reconnect delay */
const MAX_RECONNECT_DELAY = 30000

// ============================================
// Utility Functions
// ============================================

/**
 * Compute snapshot proof chain hash.
 * Uses BLAKE2b to create a hash of parent snapshot info.
 */
async function computeSnapshotProof(
  parentSnapshotId: string,
  parentCiphertextHash: string,
  updateClocks: Record<string, number>
): Promise<string> {
  const sodium = await getSodium()

  // Build proof data: parentSnapshotId || parentCiphertextHash || sorted(updateClocks)
  const clocksJson = JSON.stringify(
    Object.entries(updateClocks).sort(([a], [b]) => a.localeCompare(b))
  )
  const proofInput = `${parentSnapshotId}:${parentCiphertextHash}:${clocksJson}`

  // Hash with BLAKE2b (32 bytes)
  const proofBytes = sodium.crypto_generichash(32, sodium.from_string(proofInput))
  return sodium.to_base64(proofBytes, sodium.base64_variants.ORIGINAL)
}

// ============================================
// SecureSync class
// ============================================

/**
 * SecureSync - E2EE WebSocket synchronization for Yjs
 */
export class SecureSync {
  private doc: Y.Doc
  private documentId: string
  private workspaceId: string
  private serverUrl: string
  private token: string | null
  private options: SecureConnectionOptions

  private ws: WebSocket | null = null
  private awareness: Awareness | null = null
  private _connected = false
  private _destroyed = false
  private _shouldConnect = true
  private reconnectAttempts = 0
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null

  // Event listeners
  private statusListeners: Set<StatusEventHandler> = new Set()

  private dek: Uint8Array | null = null
  private signingKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null
  private publicKeyBase64: string | null = null

  // Ephemeral session state for awareness
  private ephemeralSession: EphemeralSession | null = null

  // Parent snapshot ciphertext hash for proof chain
  private parentSnapshotCiphertextHash: string = ''

  private state: SyncState = {
    status: 'disconnected',
    lastSeq: 0,
    localClock: 0,
    currentSnapshotId: null,
    updateClocks: new Map(),
    error: null,
  }

  private pendingUpdates: Uint8Array[] = []
  private updatesSinceSnapshot = 0
  private tagUpdateDebounceTimer: ReturnType<typeof setTimeout> | null = null
  private hasUnsavedTagChanges = false

  // Event handlers
  private updateHandler: ((update: Uint8Array, origin: unknown) => void) | null = null
  private awarenessHandler: ((changes: { added: number[]; updated: number[]; removed: number[] }, origin: unknown) => void) | null = null

  constructor(
    serverUrl: string,
    doc: Y.Doc,
    documentId: string,
    options: SecureConnectionOptions
  ) {
    this.serverUrl = serverUrl
    this.doc = doc
    this.documentId = documentId
    this.workspaceId = options.workspaceId
    this.token = options.token ?? null
    this.options = options
  }

  /**
   * Initialize the secure sync connection.
   * Must be called before connect().
   */
  async initialize(): Promise<void> {
    const keyManager = getKeyManager()
    await keyManager.initialize()

    // Verify session is unlocked
    if (!keyManager.isUnlocked) {
      throw new SessionLockedError()
    }

    // Get signing key pair
    this.signingKeyPair = keyManager.getSigningKeyPair()
    const publicKeys = await keyManager.getPublicKeysBase64()
    this.publicKeyBase64 = publicKeys.signingPublicKey

    // Get KEK for this workspace
    const fetchKek = this.options.fetchKek ?? (async () => {
      const response = await getMyWorkspaceKey({ id: this.workspaceId })
      return response.encryptedKek
    })

    const kek = await keyManager.getWorkspaceKek(this.workspaceId, fetchKek)

    // Get DEK for this document
    const fetchDek = this.options.fetchDek ?? (async () => {
      const response = await getDocumentKey({ id: this.documentId })
      return { encryptedDek: response.encryptedDek, nonce: response.nonce }
    })

    this.dek = await keyManager.getDocumentDek(this.documentId, kek, fetchDek)

    // Create ephemeral session for awareness
    this.ephemeralSession = await createEphemeralSession()

    // Initialize Awareness
    const { Awareness } = await import('y-protocols/awareness')
    this.awareness = new Awareness(this.doc)

    // Attach doc listeners early to capture all updates (including clock 0).
    // Updates will be queued in pendingUpdates until WebSocket connects.
    this.attachDocListeners()
  }

  /**
   * Get the Awareness instance.
   */
  getAwareness(): Awareness {
    if (!this.awareness) {
      throw new Error('SecureSync not initialized. Call initialize() first.')
    }
    return this.awareness
  }

  /**
   * Check if connected.
   */
  get connected(): boolean {
    return this._connected
  }

  /**
   * Get/set whether the connection should be active.
   */
  get shouldConnect(): boolean {
    return this._shouldConnect
  }

  set shouldConnect(value: boolean) {
    this._shouldConnect = value
    if (value && !this._connected && !this.ws) {
      this.connect()
    } else if (!value && this._connected) {
      this.disconnect()
    }
  }

  /**
   * Get current sync state.
   */
  get syncState(): SyncState {
    return { ...this.state }
  }

  /**
   * Add event listener.
   */
  on(event: 'status', handler: StatusEventHandler): void {
    if (event === 'status') {
      this.statusListeners.add(handler)
    }
  }

  /**
   * Remove event listener.
   */
  off(event: 'status', handler: StatusEventHandler): void {
    if (event === 'status') {
      this.statusListeners.delete(handler)
    }
  }

  /**
   * Emit status event.
   */
  private emitStatus(status: 'connecting' | 'connected' | 'disconnected'): void {
    const event: StatusEvent = { status }
    for (const handler of this.statusListeners) {
      try {
        handler(event)
      } catch (err) {
        console.error('[SecureSync] Error in status handler:', err)
      }
    }
  }

  /**
   * Connect to the WebSocket server.
   */
  connect(): void {
    if (this._destroyed) return
    if (this.ws) return // Already connected or connecting

    this.setState({ status: 'connecting', error: null })
    this.emitStatus('connecting')

    // Build WebSocket URL
    const params = new URLSearchParams()
    if (this.token) {
      params.set('token', this.token)
    }
    const queryString = params.toString()
    const wsUrl = `${this.serverUrl}/${this.documentId}${queryString ? '?' + queryString : ''}`

    this.ws = new WebSocket(wsUrl)
    this.ws.binaryType = 'arraybuffer'

    this.ws.onopen = this.handleOpen.bind(this)
    this.ws.onmessage = this.handleMessage.bind(this)
    this.ws.onclose = this.handleClose.bind(this)
    this.ws.onerror = this.handleError.bind(this)
  }

  /**
   * Disconnect from the WebSocket server.
   */
  disconnect(): void {
    this.cancelReconnect()

    if (this.ws) {
      this.ws.onopen = null
      this.ws.onmessage = null
      this.ws.onclose = null
      this.ws.onerror = null
      this.ws.close()
      this.ws = null
    }

    this._connected = false
    this.setState({ status: 'disconnected' })
    this.emitStatus('disconnected')
    this.detachDocListeners()
  }

  /**
   * Destroy the sync instance.
   */
  destroy(): void {
    this._destroyed = true

    // Flush pending tag update before destroying
    if (this.tagUpdateDebounceTimer) {
      clearTimeout(this.tagUpdateDebounceTimer)
      this.tagUpdateDebounceTimer = null
    }
    // Fire and forget - don't wait for tag update to complete
    if (this.hasUnsavedTagChanges) {
      this.updateDocumentTags().catch(() => {
        // Ignore errors on destroy
      })
    }

    this.disconnect()

    if (this.awareness) {
      this.awareness.destroy()
      this.awareness = null
    }

    // Clear keys from memory
    if (this.dek) {
      this.dek.fill(0)
      this.dek = null
    }
    if (this.signingKeyPair) {
      this.signingKeyPair.privateKey.fill(0)
      this.signingKeyPair = null
    }

    // Clear ephemeral session
    this.ephemeralSession = null
  }

  // ============================================
  // WebSocket handlers
  // ============================================

  private async handleOpen(): Promise<void> {
    this._connected = true
    this.reconnectAttempts = 0
    this.setState({ status: 'syncing' })
    this.emitStatus('connected')

    // Doc listeners are already attached in initialize().
    // Flush any updates that were queued before connection was ready.
    await this.flushPendingUpdates()

    // Send initialize message to announce presence (4-step handshake)
    await this.sendInitializeMessage()
  }

  /**
   * Flush pending updates that were queued before WebSocket connected.
   */
  private async flushPendingUpdates(): Promise<void> {
    if (this.pendingUpdates.length === 0) return

    const updates = [...this.pendingUpdates]
    this.pendingUpdates = []

    for (const update of updates) {
      await this.handleLocalUpdate(update)
    }
  }

  /**
   * Send initialize message to announce presence to other clients.
   */
  private async sendInitializeMessage(): Promise<void> {
    // Capture references at the start to avoid race conditions during async operations
    const ws = this.ws
    const dek = this.dek
    const signingKeyPair = this.signingKeyPair
    const publicKeyBase64 = this.publicKeyBase64
    const ephemeralSession = this.ephemeralSession

    if (!this._connected || !ws || !dek || !signingKeyPair || !publicKeyBase64 || !ephemeralSession) {
      return
    }

    try {
      const publicData: EphemeralPublicDataFromEphemeral = {
        docId: this.documentId,
        pubKey: publicKeyBase64,
      }

      const { message, updatedSession } = await createInitializeMessage(
        publicData,
        dek,
        signingKeyPair,
        ephemeralSession
      )
      this.ephemeralSession = updatedSession

      // Check if WebSocket is still open before sending
      if (ws.readyState !== WebSocket.OPEN) {
        return
      }

      ws.send(JSON.stringify({ type: 'awareness', ...message }))
    } catch (err) {
      console.error('[SecureSync] Error sending initialize message:', err)
    }
  }

  private async handleMessage(event: MessageEvent): Promise<void> {
    try {
      // Parse message
      let message: ServerMessage
      if (typeof event.data === 'string') {
        message = JSON.parse(event.data)
      } else {
        // Binary message - convert to string then parse
        const text = new TextDecoder().decode(event.data)
        message = JSON.parse(text)
      }

      await this.processMessage(message)
    } catch (err) {
      console.error('[SecureSync] Error processing message:', err)
    }
  }

  private handleClose(event: CloseEvent): void {
    this._connected = false
    this.ws = null
    // Don't detach listeners here - keep capturing updates for when we reconnect.
    // Listeners will be detached in disconnect() or destroy().

    if (!this._destroyed && event.code !== 1000 && this._shouldConnect) {
      // Abnormal close - attempt reconnect
      this.scheduleReconnect()
      this.emitStatus('disconnected')
    } else {
      this.setState({ status: 'disconnected' })
      this.emitStatus('disconnected')
    }
  }

  private handleError(_event: Event): void {
    this.setState({ status: 'error', error: 'WebSocket error' })
  }

  // ============================================
  // Message processing
  // ============================================

  private async processMessage(message: ServerMessage): Promise<void> {
    if (!this.dek) {
      console.error('[SecureSync] DEK not available')
      return
    }

    if (isServerInitMessage(message)) {
      await this.handleInitMessage(message)
    } else if (isServerSyncUpdate(message)) {
      await this.handleSyncUpdate(message)
    } else if (isRealtimeMessage(message)) {
      await this.handleRelayedMessage(message)
    } else {
      console.warn('[SecureSync] Unknown message type:', message)
    }
  }

  private async handleInitMessage(message: ServerInitMessage): Promise<void> {
    try {
      const { snapshot, seqAtSnapshot } = await decryptInitSnapshot(message, this.dek!)

      // Apply snapshot to document (skip if null/empty)
      if (snapshot !== null) {
        const Y = await import('yjs')
        Y.applyUpdateV2(this.doc, snapshot, 'e2ee-remote')
      }

      this.setState({
        lastSeq: seqAtSnapshot,
        status: 'syncing',
      })
    } catch (err) {
      console.error('[SecureSync] Error processing init message:', err)
      this.setState({ status: 'error', error: 'Failed to process init message' })
    }
  }

  private async handleSyncUpdate(message: { type: 'sync_update'; update: { data: string; nonce: string; signature: string; public_key: string; seq: number } }): Promise<void> {
    try {
      const { update, seq } = await decryptSyncUpdate(message, this.dek!)

      // Apply update to document
      const Y = await import('yjs')
      Y.applyUpdateV2(this.doc, update, 'e2ee-remote')

      this.setState({ lastSeq: Math.max(this.state.lastSeq, seq) })

      // Check if we've received all sync updates
      if (this.state.status === 'syncing') {
        this.setState({ status: 'ready' })
      }
    } catch (err) {
      console.error('[SecureSync] Error processing sync_update:', err)
    }
  }

  private async handleRelayedMessage(message: { type: 'update' | 'snapshot' | 'awareness'; ciphertext: string; nonce: string; signature: string; publicData: string }): Promise<void> {
    try {
      if (message.type === 'update') {
        const { update, publicData } = await verifyAndDecryptUpdate(message, this.dek!)

        // Skip our own updates
        if (publicData.pubKey === this.publicKeyBase64) {
          return
        }

        const Y = await import('yjs')
        Y.applyUpdateV2(this.doc, update, 'e2ee-remote')

        // Update clocks
        const currentClock = this.state.updateClocks.get(publicData.pubKey) ?? 0
        if (publicData.clock > currentClock) {
          this.state.updateClocks.set(publicData.pubKey, publicData.clock)
        }

        this.updatesSinceSnapshot++
      } else if (message.type === 'snapshot') {
        const { snapshot, publicData } = await verifyAndDecryptSnapshot(message, this.dek!)

        // Skip our own snapshots
        if (publicData.pubKey === this.publicKeyBase64) {
          return
        }

        const Y = await import('yjs')
        Y.applyUpdateV2(this.doc, snapshot, 'e2ee-remote')

        // Update snapshot info
        this.setState({ currentSnapshotId: publicData.snapshotId })
        this.updatesSinceSnapshot = 0

        // Store ciphertext hash for proof chain
        const sodium = await getSodium()
        const ciphertextBytes = await fromBase64(message.ciphertext)
        const hash = sodium.crypto_generichash(32, ciphertextBytes)
        this.parentSnapshotCiphertextHash = sodium.to_base64(hash, sodium.base64_variants.ORIGINAL)
      } else if (message.type === 'awareness') {
        await this.handleAwarenessMessage(message)
      }
    } catch (err) {
      console.error(`[SecureSync] Error processing ${message.type}:`, err)
    }
  }

  /**
   * Handle incoming awareness message with session handshake.
   */
  private async handleAwarenessMessage(message: { type: 'update' | 'snapshot' | 'awareness'; ciphertext: string; nonce: string; signature: string; publicData: string }): Promise<void> {
    if (!this.dek || !this.signingKeyPair || !this.ephemeralSession) {
      return
    }

    // Parse publicData for pubKey check (the original is a Base64 string)
    const parsedPublicData = JSON.parse(atob(message.publicData)) as EphemeralPublicDataFromEphemeral

    // Skip our own messages
    if (parsedPublicData.pubKey === this.publicKeyBase64) {
      return
    }

    // Convert wire format to EphemeralMessage (publicData stays as Base64 string)
    const ephemeralMessage: EphemeralMessage = {
      ciphertext: message.ciphertext,
      nonce: message.nonce,
      signature: message.signature,
      publicData: message.publicData,
    }

    // Verify, decrypt, and handle session handshake
    const result = await verifyAndDecryptEphemeralMessage(
      ephemeralMessage,
      this.dek,
      this.documentId,
      this.ephemeralSession,
      this.signingKeyPair
    )

    // Update session state
    if (result.validSessions) {
      this.ephemeralSession = {
        ...this.ephemeralSession,
        validSessions: result.validSessions,
      }
    }

    // Send proof response if requested
    if (result.proof) {
      await this.sendProofResponse(
        parsedPublicData,
        result.proof,
        result.requestProof ?? false
      )
    }

    // Apply awareness update if content is available
    if (result.content && this.awareness) {
      try {
        const { applyAwarenessUpdate } = await import('y-protocols/awareness')
        applyAwarenessUpdate(this.awareness, result.content, null)
      } catch (err) {
        console.error('[SecureSync] Error applying awareness update:', err)
      }
    }
  }

  /**
   * Send proof response message.
   */
  private async sendProofResponse(
    _remotePublicData: EphemeralPublicDataFromEphemeral,
    proof: Uint8Array,
    requestProof: boolean
  ): Promise<void> {
    // Capture references at the start to avoid race conditions during async operations
    const ws = this.ws
    const dek = this.dek
    const signingKeyPair = this.signingKeyPair
    const publicKeyBase64 = this.publicKeyBase64
    const ephemeralSession = this.ephemeralSession

    if (!this._connected || !ws || !dek || !signingKeyPair || !publicKeyBase64 || !ephemeralSession) {
      return
    }

    try {
      const publicData: EphemeralPublicDataFromEphemeral = {
        docId: this.documentId,
        pubKey: publicKeyBase64,
      }

      const messageType = requestProof ? 'proofAndRequestProof' : 'proof'
      const { message, updatedSession } = await createEphemeralMessage(
        proof,
        messageType,
        publicData,
        dek,
        signingKeyPair,
        ephemeralSession
      )
      this.ephemeralSession = updatedSession

      // Check if WebSocket is still open before sending
      if (ws.readyState !== WebSocket.OPEN) {
        return
      }

      ws.send(JSON.stringify({ type: 'awareness', ...message }))
    } catch (err) {
      console.error('[SecureSync] Error sending proof response:', err)
    }
  }

  // ============================================
  // Local change handlers
  // ============================================

  private attachDocListeners(): void {
    // Doc update listener
    this.updateHandler = (update: Uint8Array, origin: unknown) => {
      if (origin === 'e2ee-remote') {
        return // Don't re-broadcast remote updates
      }
      this.handleLocalUpdate(update).catch(console.error)
    }
    this.doc.on('updateV2', this.updateHandler)

    // Awareness listener
    if (this.awareness) {
      this.awarenessHandler = ({ added, updated, removed }, origin) => {
        if (origin === 'e2ee-remote') {
          return
        }
        const changedClients = [...added, ...updated, ...removed]
        this.handleLocalAwarenessChange(changedClients).catch(console.error)
      }
      this.awareness.on('update', this.awarenessHandler)
    }
  }

  private detachDocListeners(): void {
    if (this.updateHandler) {
      this.doc.off('updateV2', this.updateHandler)
      this.updateHandler = null
    }

    if (this.awareness && this.awarenessHandler) {
      this.awareness.off('update', this.awarenessHandler)
      this.awarenessHandler = null
    }
  }

  private async handleLocalUpdate(update: Uint8Array): Promise<void> {
    // Capture references at the start to avoid race conditions during async operations
    const ws = this.ws
    const dek = this.dek
    const signingKeyPair = this.signingKeyPair
    const publicKeyBase64 = this.publicKeyBase64

    if (!this._connected || !ws || !dek || !signingKeyPair || !publicKeyBase64) {
      // Queue update for later
      this.pendingUpdates.push(update)
      return
    }

    // Increment local clock
    this.state.localClock++

    const publicData: UpdatePublicData = {
      docId: this.documentId,
      pubKey: publicKeyBase64,
      refSnapshotId: this.state.currentSnapshotId ?? '',
      clock: this.state.localClock,
    }

    try {
      const message = await createUpdate(update, dek, signingKeyPair, publicData)

      // Check if WebSocket is still open before sending
      if (ws.readyState !== WebSocket.OPEN) {
        this.pendingUpdates.push(update)
        return
      }

      ws.send(JSON.stringify(message))

      this.updatesSinceSnapshot++

      // Check if we should create a snapshot
      if (this.updatesSinceSnapshot >= SNAPSHOT_THRESHOLD) {
        await this.createAndSendSnapshot()
      }

      // Schedule debounced tag update (auto-save style: 2s after last edit)
      this.scheduleDebouncedTagUpdate()
    } catch (err) {
      console.error('[SecureSync] Error sending update:', err)
    }
  }

  /**
   * Schedule a debounced tag update.
   * Fires 2 seconds after the last edit (auto-save pattern).
   */
  private scheduleDebouncedTagUpdate(): void {
    this.hasUnsavedTagChanges = true

    if (this.tagUpdateDebounceTimer) {
      clearTimeout(this.tagUpdateDebounceTimer)
    }

    this.tagUpdateDebounceTimer = setTimeout(() => {
      this.tagUpdateDebounceTimer = null
      this.hasUnsavedTagChanges = false
      this.updateDocumentTags().catch((err) => {
        console.warn('[SecureSync] Debounced tag update failed:', err)
      })
    }, TAG_UPDATE_DEBOUNCE_MS)
  }

  private async handleLocalAwarenessChange(changedClients: number[]): Promise<void> {
    // Capture references at the start to avoid race conditions during async operations
    const ws = this.ws
    const dek = this.dek
    const signingKeyPair = this.signingKeyPair
    const publicKeyBase64 = this.publicKeyBase64
    const awareness = this.awareness
    const ephemeralSession = this.ephemeralSession

    if (!this._connected || !ws || !dek || !signingKeyPair || !publicKeyBase64 || !awareness || !ephemeralSession) {
      return
    }

    try {
      const { encodeAwarenessUpdate } = await import('y-protocols/awareness')
      const awarenessUpdate = encodeAwarenessUpdate(awareness, changedClients)

      const publicData: EphemeralPublicDataFromEphemeral = {
        docId: this.documentId,
        pubKey: publicKeyBase64,
      }

      // Use new ephemeral message API with session handshake
      const { message, updatedSession } = await createEphemeralMessage(
        awarenessUpdate,
        'message',
        publicData,
        dek,
        signingKeyPair,
        ephemeralSession
      )
      this.ephemeralSession = updatedSession

      // Check again if WebSocket is still open before sending
      if (ws.readyState !== WebSocket.OPEN) {
        return
      }

      ws.send(JSON.stringify({ type: 'awareness', ...message }))
    } catch (err) {
      console.error('[SecureSync] Error sending awareness:', err)
    }
  }

  private async createAndSendSnapshot(): Promise<void> {
    // Capture references at the start to avoid race conditions during async operations
    const ws = this.ws
    const dek = this.dek
    const signingKeyPair = this.signingKeyPair
    const publicKeyBase64 = this.publicKeyBase64

    if (!this._connected || !ws || !dek || !signingKeyPair || !publicKeyBase64) {
      return
    }

    try {
      const Y = await import('yjs')
      const snapshot = Y.encodeStateAsUpdateV2(this.doc)

      // Generate snapshot ID
      const snapshotId = await generateSessionId()

      // Build update clocks record
      const updateClocks: Record<string, number> = {}
      for (const [key, value] of this.state.updateClocks) {
        updateClocks[key] = value
      }
      // Include our own clock
      updateClocks[publicKeyBase64] = this.state.localClock

      // Compute proof chain
      const parentSnapshotProof = this.state.currentSnapshotId
        ? await computeSnapshotProof(
            this.state.currentSnapshotId,
            this.parentSnapshotCiphertextHash,
            updateClocks
          )
        : '' // No proof for first snapshot

      const publicData: SnapshotPublicData = {
        docId: this.documentId,
        pubKey: publicKeyBase64,
        snapshotId,
        parentSnapshotId: this.state.currentSnapshotId ?? '',
        parentSnapshotProof,
        parentSnapshotUpdateClocks: updateClocks,
      }

      const message = await createSnapshot(snapshot, dek, signingKeyPair, publicData)

      // Check if WebSocket is still open before sending
      if (ws.readyState !== WebSocket.OPEN) {
        return
      }

      ws.send(JSON.stringify(message))

      // Compute and store hash of our new snapshot's ciphertext for future proofs
      const sodium = await getSodium()
      const ciphertextBytes = await fromBase64(message.ciphertext)
      const hash = sodium.crypto_generichash(32, ciphertextBytes)
      this.parentSnapshotCiphertextHash = sodium.to_base64(hash, sodium.base64_variants.ORIGINAL)

      // Update state
      this.setState({ currentSnapshotId: snapshotId })
      this.updatesSinceSnapshot = 0

      // Phase 14: Extract and update tags from document content
      // Do this in background to not block the sync flow
      this.updateDocumentTags().catch((err) => {
        console.warn('[SecureSync] Error updating document tags:', err)
      })
    } catch (err) {
      console.error('[SecureSync] Error sending snapshot:', err)
    }
  }

  /**
   * Extract tags from document content and update on server.
   * Called automatically after each snapshot.
   */
  private async updateDocumentTags(): Promise<void> {
    try {
      // Extract text content from Yjs document
      const content = this.doc.getText('content').toString()
      if (!content) return

      // Dynamic import to avoid circular dependencies
      const { updateDocumentTagsFromContent } = await import('@/entities/tag')
      await updateDocumentTagsFromContent(this.documentId, this.workspaceId, content)
    } catch (err) {
      // Don't throw - tag update failure shouldn't break sync
      console.warn('[SecureSync] Tag extraction failed:', err)
    }
  }

  // ============================================
  // Reconnection
  // ============================================

  private scheduleReconnect(): void {
    if (this._destroyed || !this._shouldConnect) return

    const delay = Math.min(
      RECONNECT_DELAY * Math.pow(2, this.reconnectAttempts),
      MAX_RECONNECT_DELAY
    )

    this.reconnectAttempts++
    this.setState({ status: 'disconnected' })

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null
      if (this._shouldConnect) {
        this.connect()
      }
    }, delay)
  }

  private cancelReconnect(): void {
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
  }

  // ============================================
  // State management
  // ============================================

  private setState(updates: Partial<SyncState>): void {
    this.state = { ...this.state, ...updates }
  }
}

// ============================================
// Factory function
// ============================================

/**
 * Create a secure E2EE connection for a Yjs document.
 *
 * This replaces y-websocket's WebsocketProvider.
 *
 * @param serverUrl - WebSocket server URL
 * @param doc - Yjs document
 * @param documentId - Document ID
 * @param options - Connection options
 * @returns SecureConnection interface
 */
export async function createSecureConnection(
  serverUrl: string,
  doc: Y.Doc,
  documentId: string,
  options: SecureConnectionOptions
): Promise<SecureConnection> {
  const sync = new SecureSync(serverUrl, doc, documentId, options)
  await sync.initialize()

  if (options.connect !== false) {
    sync.connect()
  }

  return {
    awareness: sync.getAwareness(),
    get connected() {
      return sync.connected
    },
    get syncState() {
      return sync.syncState
    },
    get shouldConnect() {
      return sync.shouldConnect
    },
    set shouldConnect(value: boolean) {
      sync.shouldConnect = value
    },
    connect: () => sync.connect(),
    disconnect: () => sync.disconnect(),
    destroy: () => sync.destroy(),
    on: (event: 'status', handler: StatusEventHandler) => sync.on(event, handler),
    off: (event: 'status', handler: StatusEventHandler) => sync.off(event, handler),
  }
}
