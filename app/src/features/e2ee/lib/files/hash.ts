/**
 * SHA-256 hash computation for file encryption
 */

/**
 * Compute SHA-256 hash of data
 * @param data - Data to hash
 * @returns Hex-encoded SHA-256 hash
 */
export async function computeSha256(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as BufferSource)
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
