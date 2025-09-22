import { AuthService } from '@/shared/api'

export const userKeys = {
  me: () => ['me'] as const,
}

export { AuthService }

export const meQuery = () => ({
  queryKey: userKeys.me(),
  queryFn: () => AuthService.me(),
  staleTime: 60_000,
})

// Use-case oriented helpers
export async function login(email: string, password: string) {
  return AuthService.login({ requestBody: { email, password } })
}

export async function register(email: string, name: string, password: string) {
  return AuthService.register({ requestBody: { email, name, password } })
}

export async function me() {
  return AuthService.me()
}
