import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { blockApiRequests } from "../../support/network";
import { E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

async function idbStoreCount(page: Page, storeName: string): Promise<number> {
  return page.evaluate(async (targetStoreName) => {
    return new Promise<number>((resolve) => {
      const req = indexedDB.open("refmd-offline");
      req.onsuccess = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(targetStoreName)) {
          db.close();
          resolve(0);
          return;
        }
        const tx = db.transaction(targetStoreName, "readonly");
        const countReq = tx.objectStore(targetStoreName).count();
        countReq.onsuccess = () => {
          db.close();
          resolve(countReq.result);
        };
        countReq.onerror = () => {
          db.close();
          resolve(-1);
        };
      };
      req.onerror = () => resolve(-1);
    });
  }, storeName);
}

async function waitForOfflineState(page: Page, offline: boolean): Promise<void> {
  await expect
    .poll(() => page.evaluate(() => navigator.onLine), {
      timeout: 10_000,
      message: `navigator.onLine did not become ${String(!offline)}`,
    })
    .toBe(!offline);
}

async function waitForPendingChanges(page: Page, minimum = 1): Promise<void> {
  await expect
    .poll(() => idbStoreCount(page, "pending-changes"), {
      timeout: 30_000,
      message: "pending offline changes were not written",
    })
    .toBeGreaterThanOrEqual(minimum);
}

async function waitForPendingChangesCleared(page: Page): Promise<void> {
  await expect
    .poll(() => idbStoreCount(page, "pending-changes"), {
      timeout: 40_000,
      message: "pending offline changes were not cleared after sync",
    })
    .toBe(0);
}

function currentDocumentId(page: Page): string {
  const match = page.url().match(/\/document\/([^/?#]+)/);
  if (!match) throw new Error(`current path is not a document route: ${page.url()}`);
  return match[1];
}

async function flushDocumentSync(page: Page): Promise<void> {
  const documentId = currentDocumentId(page);
  await page
    .evaluate(
      async (id) =>
        await (
          window as Window & {
            __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
          }
        ).__refmdFlushDocumentSync?.(id),
      documentId,
    )
    .catch(() => false);
}

async function waitForDocumentSyncReady(page: Page): Promise<void> {
  const documentId = currentDocumentId(page);
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
        timeout: 60_000,
        message: `document sync did not become ready: ${JSON.stringify(states.slice(-5))}`,
      },
    )
    .toMatchObject({
      channelState: "joined",
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

test.describe.serial("Offline Editing", () => {
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
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Offline Test Doc");
    await openDocument(sharedPage, "Offline Test Doc");

    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.insertText("Hello online content");
    await expectEditorTextContains(sharedPage, "Hello online content");
  });

  test("offline edits persist, sync, and serve cached documents during outage", async () => {
    test.setTimeout(E2E_TIMEOUTS.accountSetup);

    await test.step("offline cache is populated after opening a document", async () => {
      await expect
        .poll(() => idbStoreCount(sharedPage, "document-cache"), {
          timeout: 30_000,
          message: "offline document cache was not populated",
        })
        .toBeGreaterThan(0);
    });

    await test.step("editing while offline stores pending changes to IndexedDB", async () => {
      await sharedPage.context().setOffline(true);
      await waitForOfflineState(sharedPage, true);

      const editor = sharedPage.locator(".cm-content");
      await editor.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.keyboard.press("Enter");
      await sharedPage.keyboard.insertText("Offline edit line 1");
      await expectEditorTextContains(sharedPage, "Offline edit line 1");
      await waitForPendingChanges(sharedPage);
    });

    await test.step("offline edits survive reconnection and sync to server", async () => {
      const editor = sharedPage.locator(".cm-content");
      await editor.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.keyboard.press("Enter");
      await sharedPage.keyboard.insertText("Offline edit line 2");
      await expectEditorTextContains(sharedPage, "Offline edit line 2");
      await waitForPendingChanges(sharedPage);

      await sharedPage.context().setOffline(false);
      await waitForOfflineState(sharedPage, false);
      await flushDocumentSync(sharedPage);
      await waitForDocumentSyncReady(sharedPage);
      await waitForPendingChangesCleared(sharedPage);

      await expectEditorTextContains(sharedPage, "Hello online content");
      await expectEditorTextContains(sharedPage, "Offline edit line 1");
      await expectEditorTextContains(sharedPage, "Offline edit line 2");
    });

    await test.step("offline edits persist after page reload", async () => {
      await sharedPage.reload({ waitUntil: "domcontentloaded" });

      await expect(sharedPage.locator("aside").getByText("Offline Test Doc")).toBeVisible({
        timeout: 30_000,
      });
      await openDocument(sharedPage, "Offline Test Doc");

      await expectEditorTextContains(sharedPage, "Hello online content");
      await expectEditorTextContains(sharedPage, "Offline edit line 1");
      await expectEditorTextContains(sharedPage, "Offline edit line 2");
    });

    await test.step("multiple offline-online cycles preserve all content", async () => {
      const editor = sharedPage.locator(".cm-content");

      await sharedPage.context().setOffline(true);
      await waitForOfflineState(sharedPage, true);
      await editor.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.keyboard.press("Enter");
      await sharedPage.keyboard.insertText("Cycle 1 offline");
      await expectEditorTextContains(sharedPage, "Cycle 1 offline");
      await sharedPage.context().setOffline(false);
      await waitForOfflineState(sharedPage, false);
      await flushDocumentSync(sharedPage);
      await waitForDocumentSyncReady(sharedPage);
      await waitForPendingChangesCleared(sharedPage);

      await sharedPage.context().setOffline(true);
      await waitForOfflineState(sharedPage, true);
      await editor.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.keyboard.press("Enter");
      await sharedPage.keyboard.insertText("Cycle 2 offline");
      await expectEditorTextContains(sharedPage, "Cycle 2 offline");
      await sharedPage.context().setOffline(false);
      await waitForOfflineState(sharedPage, false);
      await flushDocumentSync(sharedPage);
      await waitForDocumentSyncReady(sharedPage);
      await waitForPendingChangesCleared(sharedPage);

      await expectEditorTextContains(sharedPage, "Cycle 1 offline");
      await expectEditorTextContains(sharedPage, "Cycle 2 offline");
    });

    await test.step("pending changes are cleared after successful sync", async () => {
      await waitForPendingChangesCleared(sharedPage);
    });

    await test.step("server-unreachable reload serves documents from offline cache", async () => {
      await sharedPage.reload({ waitUntil: "load" });
      await expect(sharedPage.locator("aside")).toBeVisible({ timeout: 30_000 });
      await expect(
        sharedPage.locator("aside").getByText("Offline Test Doc"),
      ).toBeVisible({ timeout: 30_000 });

      const apiBlock = await blockApiRequests(sharedPage);
      try {
        await sharedPage.evaluate(() => fetch("/api/workspaces").catch(() => null));
        await expect.poll(() => apiBlock.blockedCount()).toBeGreaterThan(0);

        await sharedPage.evaluate(() => {
          window.location.hash = "";
          window.dispatchEvent(new Event("popstate"));
        });

        const sidebar = sharedPage.locator("aside");
        const docLink = sidebar
          .getByText("Offline Test Doc")
          .or(sidebar.getByText("Untitled").first());
        await expect(docLink.first()).toBeVisible({ timeout: 60_000 });

        await docLink.first().click();
        await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 60_000 });

        const textOffline = await sharedPage.locator(".cm-content").textContent();
        expect(textOffline).toContain("Offline edit line 2");
      } finally {
        await apiBlock.unblock();
      }
    });
  });
});
