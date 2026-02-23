/**
 * Device API & SSE URLs
 */

import type { components } from './schema'
import { api, unwrap, API_BASE } from './core'

export const deviceApi = {
  async createPendingDevice(body: components['schemas']['CreatePendingDeviceRequest']) {
    return unwrap(await api.POST('/api/devices/pending', { body }))
  },

  async listPendingDevices() {
    return unwrap(await api.GET('/api/devices/pending'))
  },

  async getSas(pendingDeviceId: string) {
    return unwrap(await api.GET('/api/devices/pending/{id}/sas', {
      params: { path: { id: pendingDeviceId } },
    }))
  },

  async approveDevice(
    pendingDeviceId: string,
    body: components['schemas']['ApproveDeviceRequest']
  ) {
    return unwrap(await api.POST('/api/devices/pending/{id}/approve', {
      params: { path: { id: pendingDeviceId } },
      body,
    }))
  },

  async rejectPendingDevice(pendingDeviceId: string) {
    unwrap(await api.DELETE('/api/devices/pending/{id}', {
      params: { path: { id: pendingDeviceId } },
    }))
  },

  async listDevices() {
    return unwrap(await api.GET('/api/devices'))
  },

  async revokeDevice(deviceId: string, body: components['schemas']['RevokeDeviceRequest']) {
    return unwrap(await api.DELETE('/api/devices/{id}', {
      params: { path: { id: deviceId } },
      body,
    }))
  },

  async distributeUmk(deviceId: string, body: components['schemas']['DistributeUmkRequest']) {
    return unwrap(await api.POST('/api/devices/{id}/keys/umk', {
      params: { path: { id: deviceId } },
      body,
    }))
  },

  async getDeviceUmk(deviceId: string) {
    return unwrap(await api.GET('/api/devices/{id}/keys/umk', {
      params: { path: { id: deviceId } },
    }))
  },
}

/**
 * SSE (Server-Sent Events) URL builders
 */
export const sseUrls = {
  deviceEvents(): string {
    return `${API_BASE}/api/devices/events`
  },

  pendingDeviceEvents(pendingDeviceId: string): string {
    return `${API_BASE}/api/devices/pending/${pendingDeviceId}/events`
  },

  workspaceEvents(): string {
    return `${API_BASE}/api/workspaces/events`
  },
}
