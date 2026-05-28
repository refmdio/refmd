const revokingWorkspaces = new Map<string, number>();
const revokingApplications = new Map<string, number>();
const applicationRevocationGraceTimers = new Map<string, ReturnType<typeof setTimeout>>();
const inFlightRequests = new Map<string, number>();
const idleWaiters = new Map<string, Set<() => void>>();
const APPLICATION_REVOCATION_GRACE_MS = 5_000;

export function beginPluginRuntimeWorkspaceRevocation(workspaceId: string): void {
  revokingWorkspaces.set(workspaceId, (revokingWorkspaces.get(workspaceId) ?? 0) + 1);
}

export function releasePluginRuntimeWorkspaceRevocation(workspaceId: string): void {
  const count = revokingWorkspaces.get(workspaceId);
  if (!count) return;
  if (count === 1) {
    revokingWorkspaces.delete(workspaceId);
  } else {
    revokingWorkspaces.set(workspaceId, count - 1);
  }
}

export function isPluginRuntimeWorkspaceRevoking(workspaceId: string): boolean {
  return (revokingWorkspaces.get(workspaceId) ?? 0) > 0;
}

export function beginPluginRuntimeApplicationRevocation(applicationId: string): void {
  clearApplicationRevocationGrace(applicationId);
  revokingApplications.set(applicationId, (revokingApplications.get(applicationId) ?? 0) + 1);
}

export function releasePluginRuntimeApplicationRevocation(applicationId: string): void {
  const count = revokingApplications.get(applicationId);
  if (!count) {
    clearApplicationRevocationGrace(applicationId);
    return;
  }
  if (count === 1) {
    revokingApplications.delete(applicationId);
    retainApplicationRevocationGrace(applicationId);
  } else {
    revokingApplications.set(applicationId, count - 1);
  }
}

export function isPluginRuntimeApplicationRevoking(applicationId: string): boolean {
  return (
    (revokingApplications.get(applicationId) ?? 0) > 0 ||
    applicationRevocationGraceTimers.has(applicationId)
  );
}

export async function guardedPluginRuntimeWorkspaceRequest<T>(
  workspaceId: string,
  run: () => Promise<T>,
): Promise<T | null> {
  if (isPluginRuntimeWorkspaceRevoking(workspaceId)) return null;
  retainPluginRuntimeWorkspaceRequest(workspaceId);
  try {
    if (isPluginRuntimeWorkspaceRevoking(workspaceId)) return null;
    return await run();
  } finally {
    releasePluginRuntimeWorkspaceRequest(workspaceId);
  }
}

export async function waitForPluginRuntimeWorkspaceIdle(workspaceId: string): Promise<void> {
  while ((inFlightRequests.get(workspaceId) ?? 0) > 0) {
    await new Promise<void>((resolve) => {
      let waiters = idleWaiters.get(workspaceId);
      if (!waiters) {
        waiters = new Set();
        idleWaiters.set(workspaceId, waiters);
      }
      waiters.add(resolve);
    });
  }
}

function retainPluginRuntimeWorkspaceRequest(workspaceId: string): void {
  inFlightRequests.set(workspaceId, (inFlightRequests.get(workspaceId) ?? 0) + 1);
}

function releasePluginRuntimeWorkspaceRequest(workspaceId: string): void {
  const count = inFlightRequests.get(workspaceId);
  if (!count) return;
  if (count > 1) {
    inFlightRequests.set(workspaceId, count - 1);
    return;
  }
  inFlightRequests.delete(workspaceId);
  const waiters = idleWaiters.get(workspaceId);
  if (!waiters) return;
  idleWaiters.delete(workspaceId);
  for (const resolve of waiters) {
    resolve();
  }
}

function retainApplicationRevocationGrace(applicationId: string): void {
  clearApplicationRevocationGrace(applicationId);
  applicationRevocationGraceTimers.set(
    applicationId,
    setTimeout(() => {
      applicationRevocationGraceTimers.delete(applicationId);
    }, APPLICATION_REVOCATION_GRACE_MS),
  );
}

function clearApplicationRevocationGrace(applicationId: string): void {
  const timer = applicationRevocationGraceTimers.get(applicationId);
  if (!timer) return;
  clearTimeout(timer);
  applicationRevocationGraceTimers.delete(applicationId);
}
