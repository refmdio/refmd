export {
  register,
  login,
  getCurrentUser,
  logout,
  ApiRequestError,
  type RegistrationResult,
  type LoginResult,
} from './useAuth'

// Re-export MeResponse from generated schema
export type { components } from '@/shared/api'
