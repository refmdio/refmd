import { expect, test, type Page } from "@playwright/test";
import {
  createDocument,
  indexedDbKeys,
  openDocument,
  registerAccount,
} from "./helpers";

let sharedPage: Page;

test.describe.serial("Background Cache Prefetch", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
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

    const cdp = await sharedPage.context().newCDPSession(sharedPage);
    await cdp.send("Fetch.enable", {
      patterns: [
        { urlPattern: "http://localhost:*/api/auth/*", requestStage: "Request" },
        { urlPattern: "http://localhost:*/api/documents*", requestStage: "Request" },
        { urlPattern: "http://localhost:*/api/workspaces*", requestStage: "Request" },
        { urlPattern: "http://localhost:*/api/encryption/*", requestStage: "Request" },
        { urlPattern: "http://localhost:*/api/settings*", requestStage: "Request" },
        { urlPattern: "http://localhost:*/api/socket/*", requestStage: "Request" },
      ],
    });
    cdp.on("Fetch.requestPaused", async (event) => {
      try {
        await cdp.send("Fetch.failRequest", {
          requestId: event.requestId,
          errorReason: "InternetDisconnected",
        });
      } catch {
        // Ignore detached-session races during teardown.
      }
    });

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
    } finally {
      await cdp.send("Fetch.disable").catch(() => {});
      await cdp.detach().catch(() => {});
    }
  });
});
