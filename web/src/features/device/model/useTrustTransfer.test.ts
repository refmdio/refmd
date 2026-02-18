/**
 * Tests for useTrustTransfer reducer and pure helpers.
 */

import { describe, it, expect, vi } from 'vitest'
import {
  pendingReducer,
  handleNonPendingResult,
  type PendingState,
  type PendingAction,
  type TrustTransferResult,
} from './useTrustTransfer'

// Minimal stubs for required fields (only phase-transition logic matters)
const stubDeviceKeyChangePayload = {
  devices: [{ id: 'd1', name: 'D1', signing_public_key: '', ecdh_public_key: '' }],
  stateResponse: {} as PendingState extends { phase: 'device_key_change'; stateResponse: infer R } ? R : never,
  transferNonce: new Uint8Array([1]),
  deviceId: 'dev1',
  ecdhPrivateKey: new Uint8Array([2]),
  userId: 'user1',
} satisfies Omit<Extract<PendingAction, { type: 'ENTER_DEVICE_KEY_CHANGE' }>, 'type'>

describe('pendingReducer', () => {
  it('ENTER_DEVICE_KEY_CHANGE transitions from idle', () => {
    const state = pendingReducer(
      { phase: 'idle' },
      { type: 'ENTER_DEVICE_KEY_CHANGE', ...stubDeviceKeyChangePayload },
    )
    expect(state.phase).toBe('device_key_change')
    if (state.phase === 'device_key_change') {
      expect(state.devices).toHaveLength(1)
      expect(state.deviceId).toBe('dev1')
    }
  })

  it('ENTER_SENDER_KEY_CHANGE transitions to sender phase', () => {
    const state = pendingReducer(
      { phase: 'idle' },
      { type: 'ENTER_SENDER_KEY_CHANGE', senderDeviceId: 'sender1', importParams: {} as any },
    )
    expect(state.phase).toBe('sender_key_change')
    if (state.phase === 'sender_key_change') {
      expect(state.senderDeviceId).toBe('sender1')
    }
  })

  it('RESET returns to idle from any phase', () => {
    expect(
      pendingReducer(
        { phase: 'device_key_change', ...stubDeviceKeyChangePayload } as PendingState,
        { type: 'RESET' },
      ).phase,
    ).toBe('idle')

    expect(
      pendingReducer(
        { phase: 'sender_key_change', senderDeviceId: 'x', importParams: {} as any },
        { type: 'RESET' },
      ).phase,
    ).toBe('idle')
  })
})

describe('handleNonPendingResult', () => {
  it('dispatches RESET and calls onComplete for success', () => {
    const dispatch = vi.fn()
    let completed = false
    let errMsg: string | null = null
    handleNonPendingResult(
      { status: 'success' } as TrustTransferResult,
      dispatch,
      () => { completed = true },
      (msg) => { errMsg = msg },
    )
    expect(dispatch).toHaveBeenCalledWith({ type: 'RESET' })
    expect(completed).toBe(true)
    expect(errMsg).toBe(null)
  })

  it('dispatches RESET and calls onComplete for skipped', () => {
    const dispatch = vi.fn()
    let completed = false
    handleNonPendingResult(
      { status: 'skipped', reason: 'no state' } as TrustTransferResult,
      dispatch,
      () => { completed = true },
      () => {},
    )
    expect(dispatch).toHaveBeenCalledWith({ type: 'RESET' })
    expect(completed).toBe(true)
  })

  it('dispatches RESET and calls onError for security_abort', () => {
    const dispatch = vi.fn()
    let errMsg = ''
    handleNonPendingResult(
      { status: 'security_abort', message: 'tampered' } as TrustTransferResult,
      dispatch,
      () => {},
      (msg) => { errMsg = msg },
    )
    expect(dispatch).toHaveBeenCalledWith({ type: 'RESET' })
    expect(errMsg).toBe('tampered')
  })

  it('dispatches RESET and calls onComplete for retryable_error (non-abort)', () => {
    const dispatch = vi.fn()
    let completed = false
    handleNonPendingResult(
      { status: 'retryable_error', message: 'timeout' } as TrustTransferResult,
      dispatch,
      () => { completed = true },
      () => {},
    )
    expect(dispatch).toHaveBeenCalledWith({ type: 'RESET' })
    expect(completed).toBe(true)
  })
})
