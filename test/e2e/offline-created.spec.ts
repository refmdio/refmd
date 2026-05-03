import { expect, test, type Page } from "@playwright/test";
import {
  expectEditorTextContains,
  indexedDbKeys,
  openDocument,
  registerAccount,
  waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;
const OFFLINE_CREATED_TEXT = "offline-created reconnect keeps this content";

test.describe.serial("Offline-Created Document Sync", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account, cache KEK, and go offline", async () => {
    test.setTimeout(180_000);

    await registerAccount(sharedPage);

    await sharedPage.locator("aside button").first().click();
    await sharedPage.locator('input[placeholder="Document title"]').fill("Offline Seed Doc");
    await sharedPage.getByText("Create", { exact: true }).click();
    await expect(sharedPage.locator("aside").getByText("Offline Seed Doc")).toBeVisible({
      timeout: 10_000,
    });
    await openDocument(sharedPage, "Offline Seed Doc");

    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "offline-kek-cache")).length, {
        timeout: 30_000,
        message: "workspace KEK was not cached for offline document creation",
      })
      .toBeGreaterThan(0);

    await sharedPage.context().setOffline(true);
    await sharedPage.waitForTimeout(2_000);
  });

  test("creating a document while offline stores it in offline-created", async () => {
    test.setTimeout(60_000);

    await sharedPage.locator("aside button").first().click();
    await sharedPage.locator('input[placeholder="Document title"]').fill("Offline Created Doc");
    await sharedPage.getByText("Create", { exact: true }).click();

    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "offline-created")).length, {
        timeout: 10_000,
        message: "offline-created entry was not persisted",
      })
      .toBeGreaterThan(0);

    const [offlineCreatedId] = await indexedDbKeys(sharedPage, "offline-created");
    if (!offlineCreatedId) {
      throw new Error("offline-created entry id was not found");
    }
    await sharedPage.evaluate((documentId) => {
      window.history.pushState({}, "", `/document/${documentId}`);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }, offlineCreatedId);
    await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
    await sharedPage.locator(".cm-content").click();
    await sharedPage.keyboard.insertText(OFFLINE_CREATED_TEXT);
  });

  test("offline-created documents sync automatically after reconnect without breaking the open editor", async () => {
    test.setTimeout(180_000);

    await sharedPage.context().setOffline(false);

    await expect
      .poll(async () => (await indexedDbKeys(sharedPage, "offline-created")).length, {
        timeout: 60_000,
        message: "offline-created queue did not drain after reconnect",
      })
      .toBe(0);

    await expect
      .poll(
        async () =>
          sharedPage.evaluate(() => ({
            hasEditor: !!document.querySelector(".cm-content, .ProseMirror"),
            failedToLoad: document.body.textContent?.includes("Failed to load document") ?? false,
          })),
        {
          timeout: 20_000,
          message: "open offline-created document did not recover cleanly after reconnect",
        },
      )
      .toEqual({
        hasEditor: true,
        failedToLoad: false,
      });
  });

  test("synced offline-created documents survive reload and can be opened", async () => {
    test.setTimeout(180_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(sharedPage);

    const editorVisibleAfterReload = await sharedPage
      .locator(".cm-content, .ProseMirror")
      .first()
      .isVisible({ timeout: 5_000 })
      .catch(() => false);

    if (!editorVisibleAfterReload) {
      const createdDocument = sharedPage.locator("aside").getByText("Offline Created Doc");
      if (!(await createdDocument.isVisible({ timeout: 30_000 }).catch(() => false))) {
        await sharedPage.reload({ waitUntil: "domcontentloaded" });
        await waitForWorkspaceReady(sharedPage);
      }
      await expect(createdDocument).toBeVisible({ timeout: 30_000 });
      await openDocument(sharedPage, "Offline Created Doc");
    }

    await expectEditorTextContains(sharedPage, OFFLINE_CREATED_TEXT);
  });
});
