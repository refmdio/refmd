/**
 * Shared types for device feature hooks
 *
 * Derived from canonical types via Pick<> to prevent drift.
 */

import type { AuthState, DeviceState } from '@/shared/model/auth-types'

export type AuthInfo = Pick<AuthState, 'userId' | 'identityKeys' | 'umk'>

export type CurrentDeviceInfo = Pick<DeviceState, 'deviceId' | 'deviceKeys'>
