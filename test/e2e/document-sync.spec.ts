import { test, expect, type Page } from "@playwright/test";
import {
  registerAccount,
  createDocument,
  openDocument,
  collectErrors,
  expectEditorTextContains,
  newE2EContext,
} from "./helpers";

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

async function focusMarkdownEditor(page: Page) {
  await page.bringToFront();
  const editor = page.locator(".cm-content").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await expect
    .poll(
      () =>
        page.evaluate(
          () => document.querySelector(".cm-content")?.getAttribute("contenteditable") ?? null,
        ),
      {
        timeout: 15_000,
        message: "CodeMirror editor did not become editable after reload",
      },
    )
    .toBe("true");

  await editor.click({ position: { x: 12, y: 12 } });
  await page.getByRole("textbox").first().click({ position: { x: 12, y: 12 } });
  await editor.evaluate((element) => {
    if (!(element instanceof HTMLElement)) return;
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    range.collapse(false);
    selection?.removeAllRanges();
    selection?.addRange(range);
    element.focus({ preventScroll: true });
  });
  return editor;
}

test.describe.serial("Document E2EE Sync", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (
      await newE2EContext(browser, { bypassCSP: true })
    ).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register and create document", async () => {
    test.setTimeout(300_000);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Sync Test Doc");
    await openDocument(sharedPage, "Sync Test Doc");
  });

  test("types content and syncs without errors", async () => {
    test.setTimeout(120_000);

    const errors = await collectErrors(sharedPage, async () => {
      const editor = sharedPage.locator(".cm-content");
      await editor.click();

      for (let i = 0; i < 50; i++) {
        await sharedPage.keyboard.insertText(`Line ${i} test. `);
        await sharedPage.keyboard.press("Enter");
        await sharedPage.waitForTimeout(100);
      }

      // Wait for updates + threshold snapshot
      await sharedPage.waitForTimeout(15000);
    });

    const syncErrors = errors.filter(
      (e) =>
        e.includes("verification_failed") ||
        e.includes("snapshot recovery failed"),
    );
    expect(syncErrors).toHaveLength(0);
  });

  test("no infinite update loop after typing stops", async () => {
    test.setTimeout(30_000);

    await sharedPage.evaluate(() => {
      (window as any).__wsUpdateCount = 0;
      const origSend = WebSocket.prototype.send;
      WebSocket.prototype.send = function (...args: any[]) {
        (window as any).__wsUpdateCount++;
        return origSend.apply(this, args);
      };
    });

    await sharedPage.waitForTimeout(5000);

    const sendCount = await sharedPage.evaluate(
      () => (window as any).__wsUpdateCount,
    );
    expect(sendCount).toBeLessThan(20);
  });

  test("content persists after reload", async () => {
    test.setTimeout(120_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(3000);

    await expect(
      sharedPage.locator("aside").getByText("Sync Test Doc"),
    ).toBeVisible({
      timeout: 30_000,
    });
    await openDocument(sharedPage, "Sync Test Doc");

    await expectEditorTextContains(sharedPage, "Line 0 test.");
    await expectEditorTextContains(sharedPage, "Line 49 test.");
  });

  test("editing after reload works without errors", async () => {
    test.setTimeout(60_000);

    const errors = await collectErrors(sharedPage, async () => {
      await focusMarkdownEditor(sharedPage);
      await sharedPage.keyboard.press("Control+End");
      await sharedPage.keyboard.press("Enter");

      for (let i = 0; i < 10; i++) {
        await sharedPage.keyboard.insertText(`After reload ${i}.`);
        await sharedPage.keyboard.press("Enter");
        await sharedPage.waitForTimeout(100);
      }

      await expectEditorTextContains(sharedPage, "After reload 9.", 10_000);
      await sharedPage.waitForTimeout(15000);
    });

    const syncErrors = errors.filter(
      (e) =>
        e.includes("verification_failed") ||
        e.includes("snapshot recovery failed"),
    );
    expect(syncErrors).toHaveLength(0);
  });

  test("post-reload edits persist after second reload", async () => {
    test.setTimeout(180_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(3000);
    await openDocument(sharedPage, "Sync Test Doc");

    await expectEditorTextContains(sharedPage, "Line 0 test.");
    await expectEditorTextContains(sharedPage, "After reload 9.");
  });

  test("clock rollback fails closed without replacing the local pin", async () => {
    test.setTimeout(90_000);

    const documentId = await getCurrentDocumentId(sharedPage);
    const corruptedClock = await corruptDocumentClockPin(
      sharedPage,
      documentId,
    );

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await expect(sharedPage.getByText("Clock rollback").first()).toBeVisible({
      timeout: 30_000,
    });

    await expect
      .poll(() => readPinnedClockMax(sharedPage, documentId), {
        timeout: 15_000,
        message: "rollback failure replaced the stale pin",
      })
      .toBe(corruptedClock);
  });
});
