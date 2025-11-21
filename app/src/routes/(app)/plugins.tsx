import { createFileRoute } from '@tanstack/react-router'

import { pluginManifestQuery } from '@/entities/plugin'

import { requireAuthGuard } from '@/features/auth'

import PluginsPage from '@/widgets/plugins/PluginsPage'

export const Route = createFileRoute('/(app)/plugins')({
  staticData: { layout: 'app' },
  beforeLoad: requireAuthGuard,
  loader: async ({ context }) => {
    await context.queryClient.ensureQueryData(pluginManifestQuery())
    return null
  },
  component: PluginsPage,
})
