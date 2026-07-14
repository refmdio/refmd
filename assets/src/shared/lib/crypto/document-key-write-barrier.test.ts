import { expect, it, vi } from "vite-plus/test";
import { beginDocumentOfflineWipe, runDocumentOfflineWrite } from "./document-key-write-barrier";

it("drains in-flight writes and blocks new writes until wipe completion", async () => {
  let finishWrite: (() => void) | undefined;
  const inFlight = runDocumentOfflineWrite(
    "document-1",
    () =>
      new Promise<void>((resolve) => {
        finishWrite = resolve;
      }),
  );

  let wipeStarted = false;
  const wipe = beginDocumentOfflineWipe("document-1").then((endWipe) => {
    wipeStarted = true;
    return endWipe;
  });
  await Promise.resolve();
  expect(wipeStarted).toBe(false);

  finishWrite?.();
  await inFlight;
  const endWipe = await wipe;

  const blockedWrite = vi.fn(async () => "blocked");
  await expect(runDocumentOfflineWrite("document-1", blockedWrite)).resolves.toBeUndefined();
  expect(blockedWrite).not.toHaveBeenCalled();

  endWipe();
  await expect(runDocumentOfflineWrite("document-1", async () => "persisted")).resolves.toBe(
    "persisted",
  );
});
