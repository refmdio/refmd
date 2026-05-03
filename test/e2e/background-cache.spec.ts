import { expect, test, type Page } from "@playwright/test";
import {
  blockApiRequests,
  createDocument,
  indexedDbKeys,
  openDocument,
  registerAccount,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;

test.describe.serial("Background Cache Prefetch", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account and create documents", async () => {
    test.setTimeout(180_000);

    await registerAccount(sharedPage);

    await createDocument(sharedPage, "Background Cached Doc A");
    await createDocument(sharedPage, "Background Cached Doc B");
    await openDocument(sharedPage, "Background Cached Doc A");
  });

  test("background caching silently prefetches unopened documents", async () => {
    test.setTimeout(60_000);

    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "document-cache")).length, {
        timeout: 40_000,
        message: "background cache did not add a second cached document",
      })
      .toBeGreaterThanOrEqual(2);
  });

  test("prefetched documents open from offline cache without prior foreground open", async () => {
    test.setTimeout(180_000);

    await sharedPage.reload({ waitUntil: "load" });
    await sharedPage.waitForTimeout(3_000);

    const apiBlock = await blockApiRequests(sharedPage);

    try {
      await sharedPage.evaluate(() => {
        window.location.hash = "";
        window.dispatchEvent(new Event("popstate"));
      });
      await sharedPage.waitForTimeout(5_000);

      await expect(sharedPage.locator("aside").getByText("Background Cached Doc B")).toBeVisible({
        timeout: 30_000,
      });

      await sharedPage.locator("aside").getByText("Background Cached Doc B").click();
      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 30_000 });
      expect(apiBlock.blockedCount()).toBeGreaterThan(0);
    } finally {
      await apiBlock.unblock();
    }
  });
});
