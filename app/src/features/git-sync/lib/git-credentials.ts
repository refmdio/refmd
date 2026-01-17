/**
 * Git Credentials Manager for KeyVault
 *
 * Handles encrypted storage of Git authentication credentials.
 * Credentials are encrypted with workspace KEK and stored on server.
 * This enables cross-device sync while maintaining E2EE security.
 */

import { createOrUpdateConfig, getConfig, deleteConfig } from '@/entities/git'

import { getKeyVaultService, encrypt, decrypt, getSodium } from '@/features/security'

export interface GitCredentials {
  repositoryUrl: string
  branchName: string
  authType: 'https-pat' | 'ssh'
  // HTTPS
  token?: string
  // SSH
  privateKey?: string
  passphrase?: string
}

interface E2EEAuthData {
  e2ee: true
  ciphertext: string  // base64 encoded
  nonce: string       // base64 encoded
}

/**
 * Save Git credentials encrypted with workspace KEK to server
 */
export async function saveGitCredentials(
  workspaceId: string,
  credentials: GitCredentials
): Promise<void> {
  const service = getKeyVaultService()
  service.ensureUnlocked()

  // Get or create workspace KEK
  const kek = await service.keyManager.getOrCreateWorkspaceKek(workspaceId)

  // Prepare auth data to encrypt
  const authDataPlain = {
    token: credentials.token,
    privateKey: credentials.privateKey,
    passphrase: credentials.passphrase,
  }

  // Encrypt with KEK
  const sodium = await getSodium()
  const plaintext = new TextEncoder().encode(JSON.stringify(authDataPlain))
  const { ciphertext, nonce } = await encrypt(kek, plaintext)

  // Encode to base64
  const ciphertextB64 = sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL)
  const nonceB64 = sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL)

  // Create E2EE auth data structure
  const e2eeAuthData: E2EEAuthData = {
    e2ee: true,
    ciphertext: ciphertextB64,
    nonce: nonceB64,
  }

  // Save to server (server stores as-is, doesn't re-encrypt)
  await createOrUpdateConfig({
    requestBody: {
      repository_url: credentials.repositoryUrl,
      branch_name: credentials.branchName || 'main',
      auth_type: credentials.authType === 'ssh' ? 'ssh' : 'token',
      auth_data: e2eeAuthData,
      auto_sync: false,
    },
  })
}

/**
 * Load Git credentials from server and decrypt with workspace KEK
 */
export async function loadGitCredentials(
  workspaceId: string
): Promise<GitCredentials | null> {
  const service = getKeyVaultService()
  service.ensureUnlocked()

  // Get config from server
  const config = await getConfig()
  if (!config) {
    return null
  }

  // Check if we have encrypted auth data
  const rawAuthData = (config as any).encrypted_auth_data
  if (!rawAuthData || !rawAuthData.e2ee) {
    // Legacy non-encrypted config - return without auth data
    return {
      repositoryUrl: config.repository_url,
      branchName: config.branch_name,
      authType: config.auth_type === 'ssh' ? 'ssh' : 'https-pat',
    }
  }

  // Get or create workspace KEK
  const kek = await service.keyManager.getOrCreateWorkspaceKek(workspaceId)

  // Decrypt auth data
  const sodium = await getSodium()
  const ciphertext = sodium.from_base64(rawAuthData.ciphertext, sodium.base64_variants.ORIGINAL)
  const nonce = sodium.from_base64(rawAuthData.nonce, sodium.base64_variants.ORIGINAL)

  const plaintext = await decrypt(kek, ciphertext, nonce)
  const authData = JSON.parse(new TextDecoder().decode(plaintext))

  return {
    repositoryUrl: config.repository_url,
    branchName: config.branch_name,
    authType: config.auth_type === 'ssh' ? 'ssh' : 'https-pat',
    token: authData.token,
    privateKey: authData.privateKey,
    passphrase: authData.passphrase,
  }
}

/**
 * Delete Git credentials from server
 */
export async function deleteGitCredentials(): Promise<void> {
  await deleteConfig()
}

/**
 * Check if Git credentials exist for a workspace
 */
export async function hasGitCredentials(): Promise<boolean> {
  try {
    const config = await getConfig()
    return config !== null
  } catch {
    return false
  }
}
