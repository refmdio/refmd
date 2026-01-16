/**
 * E2EE Tag Module
 *
 * Provides client-side tag extraction and deterministic encryption
 * for E2EE tag management.
 */

// Tag extraction
export { extractTags, extractTagsPreserveCase } from './extract'

// Deterministic encryption
export {
  encryptTagDeterministic,
  encryptTags,
  buildTagLookupTable,
  decryptTag,
  decryptTags,
  TagLookupManager,
  getTagLookupManager,
  resetTagLookupManager,
  HMAC_KEY_SIZE,
} from './deterministic'
