import { requireAuthGuard } from '@/features/auth'

export const settingsRouteConfig = {
  staticData: { layout: 'app' as const },
  beforeLoad: requireAuthGuard,
}
