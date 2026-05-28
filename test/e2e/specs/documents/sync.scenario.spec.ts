import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { collectErrors } from "../../support/diagnostics";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

async function getCurrentDocumentId(page: Page): Promise<string> {
  await expect
    .poll(() => page.url().match(/\/document\/([^/?#]+)/)?.[1] ?? "", {
      timeout: 15_000,
      message: "document route was not established",
    })
    .not.toBe("");
  return page.url().match(/\/document\/([^/?#]+)/)![1];
}

async function corruptDocumentClockPin(
  page: Page,
  documentId: string,
): Promise<number> {
  return page.evaluate(async (id) => {
    const openRequest = indexedDB.open("refmd-security");
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      openRequest.onerror = () => reject(openRequest.error);
      openRequest.onsuccess = () => resolve(openRequest.result);
    });
    const tx = db.transaction("document-state-pins", "readwrite");
    const store = tx.objectStore("document-state-pins");
    const pin = await new Promise<{
      perDeviceMaxClocks: Record<string, number>;
    }>((resolve, reject) => {
      const request = store.get(id);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
    const entries = Object.entries(pin.perDeviceMaxClocks);
    if (entries.length === 0) {
      throw new Error("document pin has no clocks to corrupt");
    }
    const corruptedClock = Math.max(...entries.map(([, clock]) => clock)) + 100;
    const [deviceKey] = entries[0];
    pin.perDeviceMaxClocks[deviceKey] = corruptedClock;
    store.put(pin);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
    return corruptedClock;
  }, documentId);
}

async function readPinnedClockMax(
  page: Page,
  documentId: string,
): Promise<number> {
  return page.evaluate(async (id) => {
    const openRequest = indexedDB.open("refmd-security");
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      openRequest.onerror = () => reject(openRequest.error);
      openRequest.onsuccess = () => resolve(openRequest.result);
    });
    const tx = db.transaction("document-state-pins", "readonly");
    const store = tx.objectStore("document-state-pins");
    const pin = await new Promise<{
      perDeviceMaxClocks: Record<string, number>;
    }>((resolve, reject) => {
      const request = store.get(id);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
    return Math.max(...Object.values(pin.perDeviceMaxClocks));
  }, documentId);
}

async function waitForDocumentSaveIdle(page: Page, documentId: string): Promise<void> {
  await page.evaluate(
    (id) =>
      (
        window as Window & {
          __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
        }
      ).__refmdFlushDocumentSync?.(id) ?? false,
    documentId,
  );

  const states: unknown[] = [];
  await expect
    .poll(
      async () => {
        const state = await page.evaluate(
          (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
          documentId,
        );
        states.push(state);
        return state;
      },
      {
        timeout: 90_000,
        message: `document did not finish saving before reload: ${JSON.stringify(states)}`,
      },
    )
    .toMatchObject({
      error: null,
      initialized: true,
      pendingSave: false,
      pendingSnapshot: false,
      pendingUpdate: false,
      reconnecting: false,
      sending: false,
      syncPaused: false,
      unsavedCanonicalText: false,
    });
}

async function waitForDocumentEditable(page: Page, documentId: string): Promise<void> {
  await expect
    .poll(
      () => page.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, documentId),
      {
        timeout: 90_000,
        message: "document did not become editable after reload",
      },
    )
    .toMatchObject({
      channelState: "joined",
      error: null,
      initialized: true,
      readOnly: false,
      reconnecting: false,
      syncPaused: false,
    });
}

async function focusMarkdownEditor(page: Page) {
  await page.bringToFront();
  const editorShell = page.locator(".cm-editor").first();
  const editor = page.locator(".cm-content").first();
  const textbox = page.getByRole("textbox").first();
  await expect(editorShell).toBeVisible({ timeout: 60_000 });
  await expect(editor).toBeVisible({ timeout: 60_000 });
  await expect(textbox).toBeVisible({ timeout: 60_000 });

  await textbox.scrollIntoViewIfNeeded();
  await textbox.click({ position: { x: 80, y: 12 }, force: true });
  await expect
    .poll(
      () =>
        page.evaluate(() => {
          const active = document.activeElement;
          return Boolean(
            document.querySelector(".cm-editor.cm-focused") ||
              active?.closest?.(".cm-editor"),
          );
        }),
      {
        timeout: 30_000,
        message: "CodeMirror editor did not receive focus after reload",
      },
    )
    .toBe(true);

  return editor;
}

test.describe.serial("Document E2EE Sync", () => {
  test.beforeAll(async ({ browser }) => {
    const context = await newE2EContext(browser, { bypassCSP: true });
    await context.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    sharedPage = await context.newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.extendedScenario);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Sync Test Doc");
    await openDocument(sharedPage, "Sync Test Doc");
  });

  test("document sync persists typed content, reload edits, and rollback failure state", async () => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("types content and syncs without errors", async () => {
      const errors = await collectErrors(sharedPage, async () => {
        const editor = sharedPage.locator(".cm-content");
        await editor.click();

        for (let i = 0; i < 50; i++) {
          await sharedPage.keyboard.insertText(`Line ${i} test. `);
          await sharedPage.keyboard.press("Enter");
          await sharedPage.waitForTimeout(E2E_DELAYS.tinyPoll);
        }

        await waitForDocumentSaveIdle(sharedPage, await getCurrentDocumentId(sharedPage));
      });

      const syncErrors = errors.filter(
        (e) =>
          e.includes("verification_failed") ||
          e.includes("snapshot recovery failed"),
      );
      expect(syncErrors).toHaveLength(0);
    });

    await test.step("no infinite update loop after typing stops", async () => {
      await sharedPage.evaluate(() => {
        (window as any).__wsUpdateCount = 0;
        const origSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function (...args: any[]) {
          (window as any).__wsUpdateCount++;
          return origSend.apply(this, args);
        };
      });

      await sharedPage.waitForTimeout(E2E_DELAYS.syncSettle);

      const sendCount = await sharedPage.evaluate(
        () => (window as any).__wsUpdateCount,
      );
      expect(sendCount).toBeLessThan(20);
    });

    await test.step("content persists after reload", async () => {
      const documentId = await getCurrentDocumentId(sharedPage);
      await sharedPage.reload({ waitUntil: "domcontentloaded" });

      await expect
        .poll(() => sharedPage.url(), {
          timeout: 30_000,
          message: "document route was not preserved after reload",
        })
        .toContain(`/document/${documentId}`);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 90_000 });
      await expectEditorTextContains(sharedPage, "Line 0 test.", 90_000);
      await expectEditorTextContains(sharedPage, "Line 49 test.", 90_000);
    });

    await test.step("editing after reload works without errors", async () => {
      const errors = await collectErrors(sharedPage, async () => {
        await waitForDocumentEditable(sharedPage, await getCurrentDocumentId(sharedPage));
        await focusMarkdownEditor(sharedPage);
        await sharedPage.keyboard.press("Control+End");
        await sharedPage.keyboard.press("Enter");

        for (let i = 0; i < 10; i++) {
          await sharedPage.keyboard.insertText(`After reload ${i}.`);
          await sharedPage.keyboard.press("Enter");
          await sharedPage.waitForTimeout(E2E_DELAYS.tinyPoll);
        }

        await expectEditorTextContains(sharedPage, "After reload 9.", 10_000);
        await waitForDocumentSaveIdle(sharedPage, await getCurrentDocumentId(sharedPage));
      });

      const syncErrors = errors.filter(
        (e) =>
          e.includes("verification_failed") ||
          e.includes("snapshot recovery failed"),
      );
      expect(syncErrors).toHaveLength(0);
    });

    await test.step("post-reload edits persist after second reload", async () => {
      const documentId = await getCurrentDocumentId(sharedPage);
      await sharedPage.reload({ waitUntil: "domcontentloaded" });
      await expect
        .poll(() => sharedPage.url(), {
          timeout: 30_000,
          message: "document route was not preserved after second reload",
        })
        .toContain(`/document/${documentId}`);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 90_000 });
      await expectEditorTextContains(sharedPage, "Line 0 test.", 90_000);
      await expectEditorTextContains(sharedPage, "After reload 9.", 90_000);
    });

    await test.step("clock rollback fails closed without replacing the local pin", async () => {
      const documentId = await getCurrentDocumentId(sharedPage);
      const corruptedClock = await corruptDocumentClockPin(
        sharedPage,
        documentId,
      );

      await sharedPage.reload({ waitUntil: "domcontentloaded" });
      if (!/\/document\//.test(sharedPage.url())) {
        await openDocument(sharedPage, "Sync Test Doc");
      }
      await expect
        .poll(() => sharedPage.locator("body").innerText(), {
          timeout: 60_000,
          message: "clock rollback error was not surfaced after reload",
        })
        .toContain("Clock rollback");

      await expect
        .poll(() => readPinnedClockMax(sharedPage, documentId), {
          timeout: 15_000,
          message: "rollback failure replaced the stale pin",
        })
        .toBe(corruptedClock);
    });
  });
});
