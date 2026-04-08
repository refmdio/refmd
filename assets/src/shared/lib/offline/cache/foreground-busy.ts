const FOREGROUND_PAUSE_CHECK_MS = 500;

let foregroundBusyCount = 0;

export function notifyForegroundDocumentOpen(): void {
  foregroundBusyCount += 1;
}

export function notifyForegroundDocumentClose(): void {
  foregroundBusyCount = Math.max(0, foregroundBusyCount - 1);
}

export async function waitForForegroundIdle(cancelled: () => boolean): Promise<void> {
  while (foregroundBusyCount > 0 && !cancelled()) {
    await new Promise((resolve) => setTimeout(resolve, FOREGROUND_PAUSE_CHECK_MS));
  }
}
