export {
  register,
  login,
  restoreSession,
  getCurrentUser,
  logout,
  secureLogout,
  ApiRequestError,
  type RegistrationResult,
  type LoginResult,
  type SessionRestoreResult,
} from './useAuth'

// Re-export MeResponse from generated schema
export type { components } from '@/shared/api'
