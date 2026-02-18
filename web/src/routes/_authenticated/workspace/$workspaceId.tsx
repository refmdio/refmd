import { createFileRoute } from '@tanstack/react-router'
import { DocumentList } from '@/widgets/document-list'

export const Route = createFileRoute('/_authenticated/workspace/$workspaceId')({
  component: WorkspacePage,
})

function WorkspacePage() {
  const { workspaceId } = Route.useParams()

  return (
    <main className="container mx-auto py-8 px-4">
      <DocumentList workspaceId={workspaceId} />
    </main>
  )
}
