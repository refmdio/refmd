import { createFileRoute } from '@tanstack/react-router'
import { WorkspaceList } from '@/widgets/workspace-list/ui/WorkspaceList'

export const Route = createFileRoute('/_authenticated/dashboard')({
  component: DashboardPage,
})

function DashboardPage() {
  return (
    <main className="container mx-auto py-8 px-4">
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>
      <WorkspaceList />
    </main>
  )
}
