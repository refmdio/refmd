/**
 * Shared API barrel — intentional FSD design.
 * The shared layer serves as the public API surface for all upper layers.
 * Consumers MAY import from submodules directly for narrower coupling.
 */
export { api, API_BASE, ApiError, getApiErrorMessage, unwrap } from './core'
export { authApi } from './auth'
export { workspaceApi } from './workspace'
export { documentApi } from './document'
export { deviceApi, sseUrls } from './device'
export { encryptionApi } from './encryption'
export { trustTransferApi } from './trust-transfer'
export type { paths, components } from './schema'
export type { PendingDevice, DocumentResponse, WorkspaceWithMembership, DeviceSSEEvent, DevicePendingEvent, TrustTransferNonceReadyEvent, DeviceSSEEventHandlers } from './types'
export { routeDeviceSSEEvent } from './types'
