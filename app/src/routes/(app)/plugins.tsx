import { createFileRoute } from '@tanstack/react-router'

import { pluginManifestQuery } from '@/entities/plugin'

import { appBeforeLoadGuard } from '@/features/auth'

import PluginsPage from '@/widgets/plugins/PluginsPage'

export const Route = createFileRoute('/(app)/plugins')({
  staticData: { layout: 'app' },
  beforeLoad: appBeforeLoadGuard,
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(pluginManifestQuery())
    return null
  },
  component: PluginsPage,
})
