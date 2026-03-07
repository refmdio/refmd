import createClient from "openapi-fetch";
import type { paths } from "./schema";

export const client = createClient<paths>({
  baseUrl: "/",
  credentials: "include",
});

export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown>) {
    super(`API error ${status}: ${JSON.stringify(body)}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

function throwIfError<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.error !== undefined) {
    throw new ApiError(result.response.status, result.error as Record<string, unknown>);
  }
  return result.data as T;
}

export { throwIfError };
