import type { RenderManyRequest, RenderManyResponse, RenderRequest, RenderResponseBody } from '@/shared/api'
import { MarkdownService } from '@/shared/api'

export type { RenderRequest as MarkdownRenderRequest, RenderResponseBody as MarkdownRenderResponse } from '@/shared/api'

export async function renderMarkdown(request: RenderRequest): Promise<RenderResponseBody> {
  return MarkdownService.renderMarkdown({ requestBody: request })
}

export async function renderMarkdownMany(request: RenderManyRequest): Promise<RenderManyResponse> {
  return MarkdownService.renderMarkdownMany({ requestBody: request })
}
