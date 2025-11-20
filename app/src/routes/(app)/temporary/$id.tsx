import { createFileRoute, useParams } from '@tanstack/react-router'

import { requireAuthGuard } from '@/features/auth'

import RouteError from '@/widgets/routes/RouteError'
import RoutePending from '@/widgets/routes/RoutePending'
import TemporaryDocumentPage from '@/widgets/temporary/TemporaryDocumentPage'

export const Route = createFileRoute('/(app)/temporary/$id')({
  staticData: { layout: 'app' },
  beforeLoad: requireAuthGuard,
  pendingComponent: () => <RoutePending label="Preparing temporary document…" />,
  errorComponent: ({ error }) => <RouteError error={error} />,
  component: TemporaryDocumentRoute,
})

function TemporaryDocumentRoute() {
  const { id } = useParams({ from: '/(app)/temporary/$id' })
  return <TemporaryDocumentPage tempId={id} />
}
