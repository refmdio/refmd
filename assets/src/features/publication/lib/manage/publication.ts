import { publicApi, type components } from "@/shared/api";

export type Publication = components["schemas"]["PublicationResponse"];

export async function getPublication(documentId: string): Promise<Publication> {
  return await publicApi.getPublication(documentId);
}
