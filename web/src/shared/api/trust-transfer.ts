/**
 * Trust Transfer API
 */

import { api, unwrap } from './core'

export const trustTransferApi = {
  async requestNonce(deviceId: string) {
    return unwrap(await api.POST('/api/trust-transfer/nonce', {
      body: { device_id: deviceId },
    }))
  },

  async submitState(body: {
    target_device_id: string
    transfer_nonce: string
    ciphertext: string
    nonce: string
    signature: string
  }) {
    unwrap(await api.POST('/api/trust-transfer/state', { body }))
  },

  async retrieveState(deviceId: string) {
    return unwrap(await api.GET('/api/trust-transfer/state', {
      params: { query: { device_id: deviceId } },
    }))
  },
}
