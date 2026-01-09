/**
 * Encrypted File Format (.rme) Types
 *
 * RefMD Encrypted file format for attachments and exports.
 */

/** Magic bytes for .rme files: "RME1" */
export const RME_MAGIC = new Uint8Array([0x52, 0x4d, 0x45, 0x31]) // "RME1"

/** Current .rme format version */
export const RME_VERSION = 1

/**
 * .rme file header structure
 */
export interface RmeHeader {
  /** Magic bytes (4 bytes): "RME1" */
  magic: Uint8Array
  /** Format version (1 byte) */
  version: number
  /** Header length in bytes (2 bytes, little-endian) */
  headerLength: number
  /** Metadata length in bytes (4 bytes, little-endian) */
  metadataLength: number
}

/**
 * Encrypted file metadata
 * This is encrypted and stored after the header
 */
export interface RmeMetadata {
  /** Original filename */
  filename: string
  /** MIME type */
  mimeType: string
  /** Original file size in bytes */
  originalSize: number
  /** SHA-256 hash of original file (hex) */
  originalHash: string
  /** Timestamp when encrypted */
  encryptedAt: string
  /** Additional metadata */
  extra?: Record<string, unknown>
}

/**
 * Complete .rme file structure (logical, not byte layout)
 */
export interface RmeFile {
  /** File header */
  header: RmeHeader
  /** Nonce for metadata encryption (24 bytes) */
  metadataNonce: Uint8Array
  /** Encrypted metadata */
  encryptedMetadata: Uint8Array
  /** Nonce for content encryption (24 bytes) */
  contentNonce: Uint8Array
  /** Encrypted content */
  encryptedContent: Uint8Array
}

/**
 * Parsed .rme file with decrypted content
 */
export interface DecryptedRmeFile {
  /** Decrypted metadata */
  metadata: RmeMetadata
  /** Decrypted content */
  content: Uint8Array
}

/**
 * File encryption options
 */
export interface EncryptFileOptions {
  /** Original filename */
  filename: string
  /** MIME type (auto-detected if not provided) */
  mimeType?: string
  /** Additional metadata */
  extra?: Record<string, unknown>
}

/**
 * Chunked encryption for large files
 */
export interface ChunkInfo {
  /** Chunk index (0-based) */
  index: number
  /** Total number of chunks */
  total: number
  /** Chunk size in bytes */
  size: number
  /** Nonce for this chunk */
  nonce: Uint8Array
}

/** Default chunk size for large file encryption (1 MB) */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024

/**
 * Validate RME magic bytes
 */
export function isRmeFile(data: Uint8Array): boolean {
  if (data.length < RME_MAGIC.length) {
    return false
  }
  return RME_MAGIC.every((byte, i) => data[i] === byte)
}

/**
 * Get file extension for .rme files
 */
export function getRmeExtension(originalFilename: string): string {
  return `${originalFilename}.rme`
}

/**
 * Remove .rme extension to get original filename
 */
export function getOriginalFilename(rmeFilename: string): string {
  if (rmeFilename.endsWith('.rme')) {
    return rmeFilename.slice(0, -4)
  }
  return rmeFilename
}
