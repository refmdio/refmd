import { ApiError } from "@/shared/api";

export function isRetryableInvitationError(error: unknown): boolean {
  if (error instanceof ApiError) return error.status >= 500;
  return true;
}
