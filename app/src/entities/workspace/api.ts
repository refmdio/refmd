import type { WorkspaceResponse } from '@/shared/api'
import { OpenAPI } from '@/shared/api'
import { request as __request } from '@/shared/api/client/core/request'

export type UpdateWorkspacePayload = {
  name?: string
  icon?: string
  description?: string
}

export function getWorkspace(id: string): Promise<WorkspaceResponse> {
  return __request(OpenAPI, {
    method: 'GET',
    url: '/api/workspaces/{id}',
    path: { id },
  }) as Promise<WorkspaceResponse>
}

export function updateWorkspace(id: string, body: UpdateWorkspacePayload): Promise<WorkspaceResponse> {
  return __request(OpenAPI, {
    method: 'PUT',
    url: '/api/workspaces/{id}',
    path: { id },
    body,
    mediaType: 'application/json',
  }) as Promise<WorkspaceResponse>
}

export function deleteWorkspace(id: string): Promise<void> {
  return __request(OpenAPI, {
    method: 'DELETE',
    url: '/api/workspaces/{id}',
    path: { id },
  }) as Promise<void>
}
