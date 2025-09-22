import { TagsService } from '@/shared/api'

export const tagKeys = {
  all: ['tags'] as const,
  list: (q?: string) => ['tags',{ q: q ?? '' }] as const,
}

export { TagsService }

// Use-case oriented helpers
export async function listTags(q?: string) {
  return TagsService.listTags({ q: q as any })
}
