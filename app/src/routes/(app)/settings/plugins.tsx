import { createFileRoute } from '@tanstack/react-router'

import { pluginManifestQuery } from '@/entities/plugin'

import { settingsRouteConfig } from '@/features/settings/config'

import PluginsPage from '@/widgets/plugins/PluginsPage'

export const Route = createFileRoute('/(app)/settings/plugins')({
  ...settingsRouteConfig,
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(pluginManifestQuery())
    return null
  },
  component: PluginsPage,
})
