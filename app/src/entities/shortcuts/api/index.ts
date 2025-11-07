import {
  getUserShortcuts as apiGetUserShortcuts,
  updateUserShortcuts as apiUpdateUserShortcuts,
} from '@/shared/api'
import type { UpdateUserShortcutRequest, UserShortcutResponse } from '@/shared/api'

export const shortcutKeys = {
  profile: () => ['shortcuts', 'profile'] as const,
}

export const shortcutProfileQuery = () => ({
  queryKey: shortcutKeys.profile(),
  queryFn: () => apiGetUserShortcuts(),
  staleTime: 5 * 60 * 1000,
})

export async function getUserShortcuts(): Promise<UserShortcutResponse> {
  return apiGetUserShortcuts()
}

export async function updateUserShortcuts(body: UpdateUserShortcutRequest): Promise<UserShortcutResponse> {
  return apiUpdateUserShortcuts({ requestBody: body })
}
