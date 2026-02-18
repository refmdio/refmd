import { Link } from '@tanstack/react-router'
import { Card, CardHeader, CardTitle, CardDescription } from '@/shared/ui/card'
import type { WorkspaceWithMembership } from '@/shared/api'

interface WorkspaceCardProps {
  data: WorkspaceWithMembership
}

export function WorkspaceCard({ data }: WorkspaceCardProps) {
  const { workspace, membership } = data

  return (
    <Link to="/workspace/$workspaceId" params={{ workspaceId: workspace.id }}>
      <Card className="hover:bg-accent/50 transition-colors cursor-pointer">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg">{workspace.name}</CardTitle>
            {membership.is_default && (
              <span className="text-xs bg-primary/10 text-primary px-2 py-1 rounded">
                Default
              </span>
            )}
          </div>
          <CardDescription>
            Role: {membership.role.name}
          </CardDescription>
        </CardHeader>
      </Card>
    </Link>
  )
}
