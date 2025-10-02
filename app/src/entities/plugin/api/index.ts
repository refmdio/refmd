import { PluginsService } from '@/shared/api'
import type { ManifestItem as ClientManifestItem } from '@/shared/api/client'

export type PluginManifestItem = ClientManifestItem

export const pluginKeys = {
  manifest: () => ['plugins', 'manifest'] as const,
}

export const pluginManifestQuery = () => ({
  queryKey: pluginKeys.manifest(),
  queryFn: () => getPluginManifest(),
  staleTime: 60_000,
})

export async function getPluginManifest(): Promise<PluginManifestItem[]> {
  return PluginsService.pluginsGetManifest()
}

export async function execPluginAction(
  pluginId: string,
  action: string,
  payload: Record<string, unknown> | undefined,
) {
  return PluginsService.pluginsExecAction({ plugin: pluginId, action, requestBody: { payload } })
}

export async function listPluginRecords(
  pluginId: string,
  docId: string,
  kind: string,
  token?: string,
) {
  return PluginsService.listRecords({ plugin: pluginId, docId, kind, token })
}

export async function createPluginRecord(
  pluginId: string,
  docId: string,
  kind: string,
  data: unknown,
  token?: string,
) {
  return PluginsService.pluginsCreateRecord({ plugin: pluginId, docId, kind, requestBody: { data }, token })
}

export async function updatePluginRecord(pluginId: string, id: string, patch: unknown) {
  return PluginsService.pluginsUpdateRecord({ plugin: pluginId, id, requestBody: { patch } })
}

export async function deletePluginRecord(pluginId: string, id: string) {
  return PluginsService.pluginsDeleteRecord({ plugin: pluginId, id })
}

export async function getPluginKv(
  pluginId: string,
  docId: string,
  key: string,
  token?: string,
) {
  return PluginsService.pluginsGetKv({ plugin: pluginId, docId, key, token })
}

export async function putPluginKv(
  pluginId: string,
  docId: string,
  key: string,
  value: unknown,
  token?: string,
) {
  return PluginsService.pluginsPutKv({ plugin: pluginId, docId, key, requestBody: { value }, token })
}

export async function installPluginFromUrl(url: string, token?: string) {
  return PluginsService.pluginsInstallFromUrl({ requestBody: { url, token } })
}

export async function uninstallPlugin(id: string) {
  return PluginsService.pluginsUninstall({ requestBody: { id } })
}
