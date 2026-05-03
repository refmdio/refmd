let sessionContextRestorer: (() => Promise<void>) | null = null;

export function setSessionContextRestorer(restorer: (() => Promise<void>) | null): void {
  sessionContextRestorer = restorer;
}

export async function restoreSessionContext(): Promise<void> {
  await sessionContextRestorer?.();
}
