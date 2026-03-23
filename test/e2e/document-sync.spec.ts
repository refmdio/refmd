import { test, expect, type Page } from "@playwright/test";
import { registerAccount, createDocument, openDocument, collectErrors } from "./helpers";

let sharedPage: Page;

test.describe.serial("Document E2EE Sync", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register and create document", async () => {
    test.setTimeout(180_000);
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
        await sharedPage.keyboard.type(`Line ${i} test. `);
        await sharedPage.keyboard.press("Enter");
        await sharedPage.waitForTimeout(100);
      }

      // Wait for updates + threshold snapshot
      await sharedPage.waitForTimeout(15000);
    });

    const syncErrors = errors.filter(
      (e) => e.includes("verification_failed") || e.includes("snapshot recovery failed"),
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

    const sendCount = await sharedPage.evaluate(() => (window as any).__wsUpdateCount);
    expect(sendCount).toBeLessThan(20);
  });

  test("content persists after reload", async () => {
    test.setTimeout(60_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(3000);

    await expect(sharedPage.locator("aside").getByText("Sync Test Doc")).toBeVisible({
      timeout: 30_000,
    });
    await openDocument(sharedPage, "Sync Test Doc");

    const text = await sharedPage.locator(".cm-content").textContent();
    expect(text).toContain("Line 0 test.");
    expect(text).toContain("Line 49 test.");
  });

  test("editing after reload works without errors", async () => {
    test.setTimeout(60_000);

    const errors = await collectErrors(sharedPage, async () => {
      const editor = sharedPage.locator(".cm-content");
      await editor.click();
      await sharedPage.keyboard.press("End");

      for (let i = 0; i < 10; i++) {
        await sharedPage.keyboard.type(`After reload ${i}. `);
        await sharedPage.keyboard.press("Enter");
        await sharedPage.waitForTimeout(100);
      }

      await sharedPage.waitForTimeout(10000);
    });

    const syncErrors = errors.filter(
      (e) => e.includes("verification_failed") || e.includes("snapshot recovery failed"),
    );
    expect(syncErrors).toHaveLength(0);
  });

  test("post-reload edits persist after second reload", async () => {
    test.setTimeout(60_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(3000);
    await openDocument(sharedPage, "Sync Test Doc");

    const text = await sharedPage.locator(".cm-content").textContent();
    expect(text).toContain("Line 0 test.");
    expect(text).toContain("After reload 9.");
  });
});
