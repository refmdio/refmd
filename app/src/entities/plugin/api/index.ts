import {
  listRecords as apiListRecords,
  pluginsCreateRecord as apiPluginsCreateRecord,
  pluginsDeleteRecord as apiPluginsDeleteRecord,
  pluginsExecAction as apiPluginsExecAction,
  pluginsGetKv as apiPluginsGetKv,
  pluginsGetManifest as apiPluginsGetManifest,
  pluginsInstallFromUrl as apiPluginsInstallFromUrl,
  pluginsPutKv as apiPluginsPutKv,
  pluginsUninstall as apiPluginsUninstall,
  pluginsUpdateRecord as apiPluginsUpdateRecord,
  OpenAPI,
} from '@/shared/api'
import type { ManifestItem as ClientManifestItem } from '@/shared/api/client'

export type PluginManifestItem = ClientManifestItem
export type PluginRecordListOptions = {
  limit?: number | null
  offset?: number | null
}

export const pluginKeys = {
  manifest: () => ['plugins', 'manifest'] as const,
}

async function withShareAuthorization<T>(token: string | undefined, fn: () => Promise<T>) {
  if (!token) return fn()
  const previous = OpenAPI.TOKEN
  OpenAPI.TOKEN = token
  try {
    return await fn()
  } finally {
    OpenAPI.TOKEN = previous
  }
}

export const pluginManifestQuery = (token?: string | null) => ({
  queryKey: token ? [...pluginKeys.manifest(), token] : pluginKeys.manifest(),
  queryFn: () => getPluginManifest(token ?? undefined),
  staleTime: 60_000,
})

export async function getPluginManifest(token?: string): Promise<PluginManifestItem[]> {
  return withShareAuthorization(token, () => apiPluginsGetManifest())
}

export async function execPluginAction(
  pluginId: string,
  action: string,
  payload: Record<string, unknown> | undefined,
  token?: string,
) {
  return withShareAuthorization(token, () =>
    apiPluginsExecAction({
      plugin: pluginId,
      action,
      requestBody: { payload },
    }),
  )
}

export async function listPluginRecords(
  pluginId: string,
  docId: string,
  kind: string,
  optionsOrToken?: PluginRecordListOptions | string,
  token?: string,
) {
  const options = typeof optionsOrToken === 'string' ? undefined : optionsOrToken
  const authToken = typeof optionsOrToken === 'string' ? optionsOrToken : token
  return withShareAuthorization(authToken, () =>
    apiListRecords({
      plugin: pluginId,
      docId,
      kind,
      limit: options?.limit ?? undefined,
      offset: options?.offset ?? undefined,
    }),
  )
}

export async function createPluginRecord(
  pluginId: string,
  docId: string,
  kind: string,
  data: unknown,
  token?: string,
) {
  return withShareAuthorization(token, () =>
    apiPluginsCreateRecord({ plugin: pluginId, docId, kind, requestBody: { data } }),
  )
}

export async function updatePluginRecord(pluginId: string, id: string, patch: unknown, token?: string) {
  return withShareAuthorization(token, () =>
    apiPluginsUpdateRecord({ plugin: pluginId, id, requestBody: { patch } }),
  )
}

export async function deletePluginRecord(pluginId: string, id: string, token?: string) {
  return withShareAuthorization(token, () => apiPluginsDeleteRecord({ plugin: pluginId, id }))
}

export async function getPluginKv(
  pluginId: string,
  docId: string,
  key: string,
  token?: string,
) {
  return withShareAuthorization(token, () => apiPluginsGetKv({ plugin: pluginId, docId, key }))
}

export async function putPluginKv(
  pluginId: string,
  docId: string,
  key: string,
  value: unknown,
  token?: string,
) {
  return withShareAuthorization(token, () =>
    apiPluginsPutKv({ plugin: pluginId, docId, key, requestBody: { value } }),
  )
}

export async function installPluginFromUrl(url: string, token?: string) {
  return apiPluginsInstallFromUrl({ requestBody: { url, token } })
}

export async function uninstallPlugin(id: string) {
  return apiPluginsUninstall({ requestBody: { id } })
}
