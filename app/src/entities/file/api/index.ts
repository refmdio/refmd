import { FilesService } from '@/shared/api'

export const fileKeys = {
  all: ['files'] as const,
}

export { FilesService }

export async function uploadAttachment(documentId: string, file: File) {
  return FilesService.uploadFile({
    formData: { file: file as any, document_id: documentId } as any,
  })
}
