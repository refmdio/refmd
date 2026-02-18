import type { components } from './schema'

export type PendingDevice = components['schemas']['PendingDeviceResponse']
export type DocumentResponse = components['schemas']['DocumentResponse']
export type WorkspaceWithMembership = components['schemas']['WorkspaceWithMembershipResponse']

/** SSE event types for device lifecycle events (shared between approval and monitoring flows) */
export type DeviceSSEEvent = DevicePendingEvent | TrustTransferNonceReadyEvent

export interface DevicePendingEvent {
  type: 'pending_created' | 'pending_approved' | 'pending_removed' | 'pending_expired'
  pending_id: string
  user_id: string
  device_id?: string
  device_name?: string
  device_type?: string
  ip_address?: string | null
  expires_at?: string
}

export interface TrustTransferNonceReadyEvent {
  type: 'trust_transfer_nonce_ready'
  new_device_id: string
  nonce: string
  user_id: string
}

/**
 * Type-safe router for DeviceSSEEvent.
 *
 * Centralizes the exhaustive switch so that adding a new event type
 * produces a single compile error here rather than in every consumer.
 */
export interface DeviceSSEEventHandlers {
  onPendingCreated?: (event: DevicePendingEvent) => void
  onPendingApproved?: (event: DevicePendingEvent) => void
  onPendingRemoved?: (event: DevicePendingEvent) => void
  onPendingExpired?: (event: DevicePendingEvent) => void
  onTrustTransferNonceReady?: (event: TrustTransferNonceReadyEvent) => void
}

export function routeDeviceSSEEvent(event: DeviceSSEEvent, handlers: DeviceSSEEventHandlers): void {
  switch (event.type) {
    case 'pending_created':
      handlers.onPendingCreated?.(event)
      break
    case 'pending_approved':
      handlers.onPendingApproved?.(event)
      break
    case 'pending_removed':
      handlers.onPendingRemoved?.(event)
      break
    case 'pending_expired':
      handlers.onPendingExpired?.(event)
      break
    case 'trust_transfer_nonce_ready':
      handlers.onTrustTransferNonceReady?.(event)
      break
    default: {
      const _exhaustive: never = event
      void _exhaustive
    }
  }
}
