import { uploadFile as apiUploadFile } from '@/shared/api'

export const fileKeys = {
  all: ['files'] as const,
}

export async function uploadAttachment(documentId: string, file: File) {
  return apiUploadFile({
    docId: documentId,
    formData: { file },
  })
}
