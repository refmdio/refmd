const PLUGIN_RUNTIME_TEARDOWN_AUDIT_FLUSH_TIMEOUT_MS = 3_000;

export async function flushPluginRuntimeTeardown(
  flushPendingAudit: () => Promise<void>,
  options: { auditFlushTimeoutMs?: number } = {},
): Promise<void> {
  const auditFlushTimeoutMs =
    options.auditFlushTimeoutMs ?? PLUGIN_RUNTIME_TEARDOWN_AUDIT_FLUSH_TIMEOUT_MS;
  await settlePluginRuntimeTeardown();
  if (!(await flushPendingAuditForTeardown(flushPendingAudit, auditFlushTimeoutMs))) return;
  await settlePluginRuntimeTeardown();
  await flushPendingAuditForTeardown(flushPendingAudit, auditFlushTimeoutMs);
}

async function settlePluginRuntimeTeardown(): Promise<void> {
  await Promise.resolve();
  await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
  await Promise.resolve();
}

async function flushPendingAuditForTeardown(
  flushPendingAudit: () => Promise<void>,
  timeoutMs: number,
): Promise<boolean> {
  const flush = flushPendingAudit().then(
    () => true,
    () => false,
  );
  if (timeoutMs <= 0) return flush;

  let timeoutId: ReturnType<typeof window.setTimeout> | undefined;
  const timeout = new Promise<false>((resolve) => {
    timeoutId = window.setTimeout(() => resolve(false), timeoutMs);
  });

  try {
    return await Promise.race([flush, timeout]);
  } finally {
    if (timeoutId !== undefined) window.clearTimeout(timeoutId);
  }
}
