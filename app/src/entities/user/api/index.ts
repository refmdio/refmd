import {
  deleteAccount as apiDeleteAccount,
  login as apiLogin,
  logout as apiLogout,
  me as apiMe,
  register as apiRegister,
  switchWorkspace as apiSwitchWorkspace,
  oauthLogin as apiOauthLogin,
} from '@/shared/api'

export const userKeys = {
  me: () => ['me'] as const,
}

export const meQuery = () => ({
  queryKey: userKeys.me(),
  queryFn: () => apiMe(),
  staleTime: 60_000,
})

// Use-case oriented helpers
export async function login(email: string, password: string) {
  return apiLogin({ requestBody: { email, password } })
}

export type OAuthLoginPayload = {
  credential?: string
  code?: string
  redirect_uri?: string
}

export async function oauthLogin(provider: string, payload: OAuthLoginPayload) {
  return apiOauthLogin({ provider, requestBody: payload })
}

export async function register(email: string, name: string, password: string) {
  return apiRegister({ requestBody: { email, name, password } })
}

export async function me() {
  return apiMe()
}

export async function deleteAccount() {
  return apiDeleteAccount()
}

export async function logout() {
  return apiLogout()
}

export async function switchWorkspace(workspaceId: string) {
  return apiSwitchWorkspace({ id: workspaceId })
}
