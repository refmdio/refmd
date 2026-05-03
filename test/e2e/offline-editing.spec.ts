import { test, expect, type Page } from "@playwright/test";
import {
  blockApiRequests,
  createDocument,
  expectEditorTextContains,
  openDocument,
  registerAccount,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;

test.describe.serial("Offline Editing", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register, create document, type initial content", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Offline Test Doc");
    await openDocument(sharedPage, "Offline Test Doc");

    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.insertText("Hello online content");
    await sharedPage.waitForTimeout(5000);
  });

  test("offline cache is populated after opening a document", async () => {
    test.setTimeout(30_000);
    const hasCache = await sharedPage.evaluate(async () => {
      return new Promise<boolean>((resolve) => {
        const req = indexedDB.open("refmd-offline");
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("document-cache", "readonly");
          const countReq = tx.objectStore("document-cache").count();
          countReq.onsuccess = () => {
            db.close();
            resolve(countReq.result > 0);
          };
          countReq.onerror = () => {
            db.close();
            resolve(false);
          };
        };
        req.onerror = () => resolve(false);
      });
    });
    expect(hasCache).toBe(true);
  });

  test("editing while offline stores pending changes to IndexedDB", async () => {
    test.setTimeout(60_000);
    await sharedPage.context().setOffline(true);
    await sharedPage.waitForTimeout(2000);

    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.press("End");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Offline edit line 1");
    await sharedPage.waitForTimeout(3000);

    const hasPending = await sharedPage.evaluate(async () => {
      return new Promise<boolean>((resolve) => {
        const req = indexedDB.open("refmd-offline");
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("pending-changes", "readonly");
          const countReq = tx.objectStore("pending-changes").count();
          countReq.onsuccess = () => {
            db.close();
            resolve(countReq.result > 0);
          };
          countReq.onerror = () => {
            db.close();
            resolve(false);
          };
        };
        req.onerror = () => resolve(false);
      });
    });
    expect(hasPending).toBe(true);
  });

  test("offline edits survive reconnection and sync to server", async () => {
    test.setTimeout(120_000);
    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.press("End");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Offline edit line 2");
    await sharedPage.waitForTimeout(2000);

    await sharedPage.context().setOffline(false);
    await sharedPage.waitForTimeout(20000);

    await expectEditorTextContains(sharedPage, "Hello online content");
    await expectEditorTextContains(sharedPage, "Offline edit line 1");
    await expectEditorTextContains(sharedPage, "Offline edit line 2");
    await sharedPage.waitForTimeout(15000);
  });

  test("offline edits persist after page reload", async () => {
    test.setTimeout(60_000);
    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(5000);

    await expect(sharedPage.locator("aside").getByText("Offline Test Doc")).toBeVisible({
      timeout: 30_000,
    });
    await openDocument(sharedPage, "Offline Test Doc");

    await expectEditorTextContains(sharedPage, "Hello online content");
    await expectEditorTextContains(sharedPage, "Offline edit line 1");
    await expectEditorTextContains(sharedPage, "Offline edit line 2");
  });

  test("multiple offline-online cycles preserve all content", async () => {
    test.setTimeout(120_000);
    const editor = sharedPage.locator(".cm-content");

    await sharedPage.context().setOffline(true);
    await sharedPage.waitForTimeout(2000);
    await editor.click();
    await sharedPage.keyboard.press("End");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Cycle 1 offline");
    await sharedPage.waitForTimeout(3000);
    await sharedPage.context().setOffline(false);
    await sharedPage.waitForTimeout(10000);

    await sharedPage.context().setOffline(true);
    await sharedPage.waitForTimeout(2000);
    await editor.click();
    await sharedPage.keyboard.press("End");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Cycle 2 offline");
    await sharedPage.waitForTimeout(3000);
    await sharedPage.context().setOffline(false);
    await sharedPage.waitForTimeout(10000);

    await expectEditorTextContains(sharedPage, "Cycle 1 offline");
    await expectEditorTextContains(sharedPage, "Cycle 2 offline");
  });

  test("pending-changes cleared after successful sync", async () => {
    test.setTimeout(30_000);
    await sharedPage.waitForTimeout(5000);
    const pendingCount = await sharedPage.evaluate(async () => {
      return new Promise<number>((resolve) => {
        const req = indexedDB.open("refmd-offline");
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction("pending-changes", "readonly");
          const countReq = tx.objectStore("pending-changes").count();
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
    });
    expect(pendingCount).toBe(0);
  });

  test("server-unreachable reload: SPA boots, offline cache serves documents", async () => {
    test.setTimeout(180_000);

    const editor = sharedPage.locator(".cm-content");

    // Accumulate offline changes
    await sharedPage.context().setOffline(true);
    await sharedPage.waitForTimeout(2000);
    await editor.click();
    await sharedPage.keyboard.press("End");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Server unreachable edit");
    await sharedPage.waitForTimeout(5000);
    await sharedPage.context().setOffline(false);
    await sharedPage.waitForTimeout(10000);

    // Reload online first (SPA + assets load normally)
    await sharedPage.reload({ waitUntil: "load" });
    await sharedPage.waitForTimeout(3000);

    const apiBlock = await blockApiRequests(sharedPage);
    try {
      // Navigate to dashboard (SPA client-side navigation, no HTML fetch needed)
      await sharedPage.evaluate(() => {
        window.location.hash = "";
        window.dispatchEvent(new Event("popstate"));
      });
      await sharedPage.waitForTimeout(5000);

      // The sidebar should show documents from offline cache
      const sidebar = sharedPage.locator("aside");
      const docLink = sidebar
        .getByText("Offline Test Doc")
        .or(sidebar.getByText("Untitled").first());
      await expect(docLink.first()).toBeVisible({ timeout: 60_000 });

      // Click document — should load from offline cache
      await docLink.first().click();
      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 60_000 });

      const textOffline = await sharedPage.locator(".cm-content").textContent();
      expect(textOffline).toContain("Server unreachable edit");
      expect(apiBlock.blockedCount()).toBeGreaterThan(0);
    } finally {
      await apiBlock.unblock();
    }
  });
});
