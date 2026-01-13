/**
 * E2EE File Encryption Module
 *
 * Provides file encryption/decryption for .rme format attachments.
 */

// Hash computation
export { computeSha256 } from './hash'

// .rme format serialization
export { serializeRme, parseRme } from './format'

// File format utilities
export { isRmeFile } from '../types/file-format'

// File encryption
export { encryptFile, type EncryptFileResult } from './encrypt'

// File decryption
export {
  decryptFile,
  decryptMetadata,
  E2EEFileError,
  E2EE_FILE_ERROR,
} from './decrypt'

// Chunked encryption for large files
export {
  isLargeFile,
  splitIntoChunks,
  encryptChunked,
  decryptChunked,
  LARGE_FILE_THRESHOLD,
  type EncryptedChunk,
} from './chunk'
