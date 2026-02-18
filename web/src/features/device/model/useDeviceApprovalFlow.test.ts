/**
 * Tests for useDeviceApprovalFlow reducer.
 */

import { describe, it, expect } from 'vitest'
import { approvalReducer, initialApprovalState, type ApprovalState } from './useDeviceApprovalFlow'

const dummyKeys = {
  signingPk: new Uint8Array([1]),
  ecdhPk: new Uint8Array([2]),
  clientNonce: new Uint8Array([3]),
}

describe('approvalReducer', () => {
  it('START_LOADING clears error and sets step', () => {
    const errState: ApprovalState = { ...initialApprovalState, step: 'error', error: 'something' }
    const next = approvalReducer(errState, { type: 'START_LOADING' })
    expect(next.step).toBe('loading')
    expect(next.error).toBe(null)
  })

  it('SAS_READY sets verify with emojis and keys', () => {
    const next = approvalReducer(initialApprovalState, {
      type: 'SAS_READY',
      sasEmojis: '🔑🔒',
      keys: dummyKeys,
    })
    expect(next.step).toBe('verify')
    expect(next.sasEmojis).toBe('🔑🔒')
    expect(next.pendingDeviceKeys).toBe(dummyKeys)
    expect(next.error).toBe(null)
  })

  it('KEYS_FETCHED stores keys without changing step', () => {
    const next = approvalReducer(initialApprovalState, { type: 'KEYS_FETCHED', keys: dummyKeys })
    expect(next.step).toBe('loading')
    expect(next.pendingDeviceKeys).toBe(dummyKeys)
  })

  it('SHOW_VERIFY preserves keys and sets verify', () => {
    const withKeys: ApprovalState = { ...initialApprovalState, pendingDeviceKeys: dummyKeys }
    const next = approvalReducer(withKeys, { type: 'SHOW_VERIFY', sasEmojis: '🎉' })
    expect(next.step).toBe('verify')
    expect(next.sasEmojis).toBe('🎉')
    expect(next.pendingDeviceKeys).toBe(dummyKeys)
  })

  it('START_APPROVING clears error', () => {
    const errState: ApprovalState = { ...initialApprovalState, step: 'verify', error: 'old' }
    const next = approvalReducer(errState, { type: 'START_APPROVING' })
    expect(next.step).toBe('approving')
    expect(next.error).toBe(null)
  })

  it('ERROR sets step and message', () => {
    const next = approvalReducer(initialApprovalState, { type: 'ERROR', message: 'failed' })
    expect(next.step).toBe('error')
    expect(next.error).toBe('failed')
  })
})
