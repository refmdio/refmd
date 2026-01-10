import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import {
  deleteAccount as apiDeleteAccount,
  listSessions as apiListSessions,
  login as apiLogin,
  logout as apiLogout,
  me as apiMe,
  register as apiRegister,
  revokeSession as apiRevokeSession,
  switchWorkspace as apiSwitchWorkspace,
  oauthLogin as apiOauthLogin,
  oauthState as apiOauthState,
  refreshSession as apiRefreshSession,
  listOauthProviders as apiListOauthProviders,
  // Security / E2EE APIs
  getE2EeStatus as apiGetSecurityStatus,
  needsMigration as apiNeedsMigration,
  migrateToE2Ee as apiMigrateUserData,
  markE2EeSetupComplete as apiMarkSecuritySetupComplete,
  getMyPublicKey as apiGetMyPublicKey,
  registerPublicKey as apiRegisterPublicKey,
  getMasterKeyBackup as apiGetMasterKeyBackup,
  storeMasterKeyBackup as apiStoreMasterKeyBackup,
  getEncryptedPrivateKey as apiGetEncryptedPrivateKey,
  storeEncryptedPrivateKey as apiStoreEncryptedPrivateKey,
} from '@/shared/api'
import type {
  SessionResponse,
  AuthProvidersResponse,
  E2eeStatusResponse,
  NeedsMigrationResponse,
  MigrationResponse,
  UserPublicKeyResponse,
  MasterKeyBackupResponse,
  EncryptedPrivateKeyResponse,
  MigrateRequest,
  RegisterPublicKeyRequest,
  StoreMasterKeyBackupRequest,
  StoreEncryptedPrivateKeyRequest,
} from '@/shared/api'

export const userKeys = {
  me: () => ['me'] as const,
}

export const userSessionKeys = {
  list: () => ['auth-sessions'] as const,
}

export const authProviderKeys = {
  list: () => ['auth-providers'] as const,
}

export const meQuery = () => ({
  queryKey: userKeys.me(),
  queryFn: () => apiMe(),
  staleTime: 60_000,
})

// Use-case oriented helpers
export async function login(email: string, password: string, options?: { remember?: boolean }) {
  return apiLogin({ requestBody: { email, password, remember_me: options?.remember ?? false } })
}

export type OAuthLoginPayload = {
  credential?: string
  code?: string
  redirect_uri?: string
  remember_me?: boolean
  state?: string
}

export async function oauthLogin(provider: string, payload: OAuthLoginPayload) {
  return apiOauthLogin({ provider, requestBody: payload })
}

export async function createOauthState(provider: string) {
  return apiOauthState({ provider })
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

export async function refreshSession() {
  return apiRefreshSession()
}

export async function listAuthProviders() {
  return apiListOauthProviders()
}

export async function listSessions() {
  return apiListSessions() as Promise<SessionResponse[]>
}

export async function revokeSession(sessionId: string) {
  return apiRevokeSession({ id: sessionId })
}

export const userSessionsQuery = () => ({
  queryKey: userSessionKeys.list(),
  queryFn: () => listSessions(),
})

export const authProvidersQuery = () => ({
  queryKey: authProviderKeys.list(),
  queryFn: () => listAuthProviders() as Promise<AuthProvidersResponse>,
  staleTime: 5 * 60 * 1000,
  retry: 2,
})

export function useUserSessions(options?: { enabled?: boolean }) {
  return useQuery({
    ...userSessionsQuery(),
    enabled: options?.enabled ?? true,
  })
}

export function useRevokeSession(options?: {
  onSuccess?: (sessionId: string) => void
  onError?: (error: unknown, sessionId: string) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sessionId: string) => apiRevokeSession({ id: sessionId }),
    onSuccess: (_data, sessionId) => {
      qc.invalidateQueries({ queryKey: userSessionKeys.list() })
      options?.onSuccess?.(sessionId)
    },
    onError: (error, sessionId) => {
      options?.onError?.(error, sessionId)
    },
  })
}

// ============================================
// Security / E2EE
// ============================================

export const securityKeys = {
  status: () => ['security', 'status'] as const,
  needsMigration: () => ['security', 'needs-migration'] as const,
  publicKey: () => ['security', 'public-key'] as const,
  masterKeyBackup: () => ['security', 'master-key-backup'] as const,
  encryptedPrivateKey: () => ['security', 'encrypted-private-key'] as const,
}

// API wrapper functions
export async function getSecurityStatus(): Promise<E2eeStatusResponse> {
  return apiGetSecurityStatus()
}

export async function checkNeedsMigration(): Promise<NeedsMigrationResponse> {
  return apiNeedsMigration()
}

export async function migrateUserData(request: MigrateRequest): Promise<MigrationResponse> {
  return apiMigrateUserData({ requestBody: request })
}

export async function markSecuritySetupComplete(): Promise<void> {
  await apiMarkSecuritySetupComplete()
}

export async function getMyPublicKey(): Promise<UserPublicKeyResponse> {
  return apiGetMyPublicKey()
}

export async function registerPublicKey(request: RegisterPublicKeyRequest): Promise<UserPublicKeyResponse> {
  return apiRegisterPublicKey({ requestBody: request })
}

export async function getMasterKeyBackup(): Promise<MasterKeyBackupResponse> {
  return apiGetMasterKeyBackup()
}

export async function storeMasterKeyBackup(request: StoreMasterKeyBackupRequest): Promise<MasterKeyBackupResponse> {
  return apiStoreMasterKeyBackup({ requestBody: request })
}

export async function getEncryptedPrivateKey(): Promise<EncryptedPrivateKeyResponse> {
  return apiGetEncryptedPrivateKey()
}

export async function storeEncryptedPrivateKey(request: StoreEncryptedPrivateKeyRequest): Promise<EncryptedPrivateKeyResponse> {
  return apiStoreEncryptedPrivateKey({ requestBody: request })
}

// Query definitions
export const securityStatusQuery = () => ({
  queryKey: securityKeys.status(),
  queryFn: () => getSecurityStatus(),
  staleTime: 30_000,
})

export const needsMigrationQuery = () => ({
  queryKey: securityKeys.needsMigration(),
  queryFn: () => checkNeedsMigration(),
  staleTime: 30_000,
})

// Re-export types
export type {
  E2eeStatusResponse as SecurityStatusResponse,
  NeedsMigrationResponse,
  MigrationResponse,
  UserPublicKeyResponse,
  MasterKeyBackupResponse,
  EncryptedPrivateKeyResponse,
  MigrateRequest,
  RegisterPublicKeyRequest,
  StoreMasterKeyBackupRequest,
  StoreEncryptedPrivateKeyRequest,
}
