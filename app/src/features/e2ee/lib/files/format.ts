/**
 * .rme binary format serialization/deserialization
 *
 * Binary layout:
 * Offset | Size | Description
 * -------|------|------------
 * 0      | 4    | Magic "RME1"
 * 4      | 1    | Version (0x01)
 * 5      | 2    | Header length (LE)
 * 7      | 4    | Metadata length (LE)
 * 11     | 24   | Metadata nonce
 * 35     | N    | Encrypted metadata
 * 35+N   | 24   | Content nonce
 * 35+N+24| M    | Encrypted content
 */

import {
  RME_MAGIC,
  RME_VERSION,
  type RmeFile,
  type RmeHeader,
} from '../types/file-format'

/** Fixed header size: magic(4) + version(1) + headerLength(2) + metadataLength(4) = 11 bytes */
const HEADER_SIZE = 11

/** Nonce size for XChaCha20-Poly1305: 24 bytes */
const NONCE_SIZE = 24

/**
 * Serialize RmeFile to binary format
 */
export function serializeRme(file: RmeFile): Uint8Array {
  const totalSize =
    HEADER_SIZE +
    NONCE_SIZE + // metadata nonce
    file.encryptedMetadata.length +
    NONCE_SIZE + // content nonce
    file.encryptedContent.length

  const buffer = new Uint8Array(totalSize)
  const view = new DataView(buffer.buffer)

  let offset = 0

  // Magic bytes "RME1"
  buffer.set(RME_MAGIC, offset)
  offset += 4

  // Version
  buffer[offset++] = RME_VERSION

  // Header length (LE)
  view.setUint16(offset, HEADER_SIZE, true)
  offset += 2

  // Metadata length (LE)
  view.setUint32(offset, file.encryptedMetadata.length, true)
  offset += 4

  // Metadata nonce
  buffer.set(file.metadataNonce, offset)
  offset += NONCE_SIZE

  // Encrypted metadata
  buffer.set(file.encryptedMetadata, offset)
  offset += file.encryptedMetadata.length

  // Content nonce
  buffer.set(file.contentNonce, offset)
  offset += NONCE_SIZE

  // Encrypted content
  buffer.set(file.encryptedContent, offset)

  return buffer
}

/**
 * Parse binary data to RmeFile structure
 * @throws Error if format is invalid
 */
export function parseRme(bytes: Uint8Array): RmeFile {
  if (bytes.length < HEADER_SIZE) {
    throw new Error('Invalid RME file: too short')
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let offset = 0

  // Magic bytes
  const magic = bytes.slice(offset, offset + 4)
  if (!magic.every((b, i) => b === RME_MAGIC[i])) {
    throw new Error('Invalid RME file: magic bytes mismatch')
  }
  offset += 4

  // Version
  const version = bytes[offset++]
  if (version !== RME_VERSION) {
    throw new Error(`Unsupported RME version: ${version}`)
  }

  // Header length
  const headerLength = view.getUint16(offset, true)
  offset += 2

  // Metadata length
  const metadataLength = view.getUint32(offset, true)
  offset += 4

  // Validate remaining length
  const expectedLength = HEADER_SIZE + NONCE_SIZE + metadataLength + NONCE_SIZE
  if (bytes.length < expectedLength) {
    throw new Error('Invalid RME file: truncated')
  }

  // Metadata nonce
  const metadataNonce = bytes.slice(offset, offset + NONCE_SIZE)
  offset += NONCE_SIZE

  // Encrypted metadata
  const encryptedMetadata = bytes.slice(offset, offset + metadataLength)
  offset += metadataLength

  // Content nonce
  const contentNonce = bytes.slice(offset, offset + NONCE_SIZE)
  offset += NONCE_SIZE

  // Encrypted content (rest of file)
  const encryptedContent = bytes.slice(offset)

  const header: RmeHeader = {
    magic,
    version,
    headerLength,
    metadataLength,
  }

  return {
    header,
    metadataNonce,
    encryptedMetadata,
    contentNonce,
    encryptedContent,
  }
}
