export function createInitCancelledError(): Error {
  const error = new Error("init_cancelled");
  error.name = "AbortError";
  return error;
}

export function isInitCancelledError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}
