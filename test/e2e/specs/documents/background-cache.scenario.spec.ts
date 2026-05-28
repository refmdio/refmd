import { expect, test, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { blockApiRequests } from "../../support/network";
import { indexedDbKeys } from "../../support/offline";
import { E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

test.describe.serial("Background Cache Prefetch", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);

    await registerAccount(sharedPage);

    await createDocument(sharedPage, "Background Cached Doc A");
    await createDocument(sharedPage, "Background Cached Doc B");
    await openDocument(sharedPage, "Background Cached Doc A");
  });

  test("prefetched documents open from offline cache without prior foreground open", async () => {
    test.setTimeout(E2E_TIMEOUTS.accountSetup);

    await test.step("background caching silently prefetches unopened documents", async () => {
      await expect
        .poll(async () => (await indexedDbKeys(sharedPage, "document-cache")).length, {
          timeout: 40_000,
          message: "background cache did not add a second cached document",
        })
        .toBeGreaterThanOrEqual(2);
    });

    await sharedPage.reload({ waitUntil: "load" });
    await expect(sharedPage.locator("aside")).toBeVisible({ timeout: 30_000 });
    const sidebar = sharedPage.locator("aside");
    const prefetchedDocument = sidebar
      .getByText("Background Cached Doc B")
      .or(sidebar.getByText("Untitled").last());
    await expect(prefetchedDocument).toBeVisible({ timeout: 60_000 });
    const apiBlock = await blockApiRequests(sharedPage);

    try {
      await sharedPage.evaluate(() => fetch("/api/workspaces").catch(() => null));
      await expect.poll(() => apiBlock.blockedCount()).toBeGreaterThan(0);

      await sharedPage.evaluate(() => {
        window.location.hash = "";
        window.dispatchEvent(new Event("popstate"));
      });

      await expect(prefetchedDocument).toBeVisible({ timeout: 30_000 });

      await prefetchedDocument.click();
      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 30_000 });
    } finally {
      await apiBlock.unblock();
    }
  });
});
