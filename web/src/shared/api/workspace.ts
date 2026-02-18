/**
 * Workspace API
 */

import { api, unwrap } from './core'

export const workspaceApi = {
  async list() {
    return unwrap(await api.GET('/api/workspaces'))
  },
}
