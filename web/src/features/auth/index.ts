export {
  register,
  login,
  restoreSession,
  restoreSessionWithPdk,
  getCurrentUser,
  logout,
  secureLogout,
  ApiRequestError,
  type RegistrationResult,
  type LoginResult,
  type LoginDeviceRequired,
  type LoginResponse,
  type SessionRestoreResult,
  type PdkSessionRestoreResult,
  type PdkFallbackRequired,
} from './useAuth'

// Re-export MeResponse from generated schema
export type { components } from '@/shared/api'
