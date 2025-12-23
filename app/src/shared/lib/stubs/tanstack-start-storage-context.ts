export function getStartContext() {
  return {
    contextAfterGlobalMiddlewares: undefined,
  } as any
}

export async function runWithStartContext<T>(_: unknown, fn: () => T | Promise<T>): Promise<T> {
  return fn()
}

