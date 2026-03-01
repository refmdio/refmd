/**
 * Invitation API (top-level acceptance endpoint)
 */

import { api, unwrap } from './core'

export const invitationApi = {
  async accept(body: { token: string }) {
    return unwrap(await api.POST('/api/workspaces/invitations/accept', { body }))
  },
}
