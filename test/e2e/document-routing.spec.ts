import { test, expect, type Page } from "@playwright/test";
import { createDocument, openContextMenu, openDocument, registerAccount } from "./helpers";

let sharedPage: Page;
let documentIdA: string;
let documentIdB: string;

function documentRouteRegex(documentId: string): RegExp {
  return new RegExp(`/document/${documentId}$`);
}

async function currentDocumentId(page: Page): Promise<string> {
  const pathname = new URL(page.url()).pathname;
  const match = pathname.match(/^\/document\/([^/]+)$/);
  if (!match) {
    throw new Error(`current path is not a document route: ${pathname}`);
  }
  return match[1];
}

async function waitForPanel(page: Page, documentId: string): Promise<void> {
  await expect
    .poll(
      async () => page.locator(`[data-panel-id^="${documentId}:"]`).count(),
      {
        timeout: 15_000,
        message: `document panel not mounted for ${documentId}`,
      },
    )
    .toBeGreaterThan(0);
}

async function openDocumentIds(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const ids = Array.from(document.querySelectorAll("[data-panel-id]"))
      .map((el) => el.getAttribute("data-panel-id") ?? "")
      .map((panelId) => panelId.split(":")[0])
      .filter((id) => id.length > 0);

    return Array.from(new Set(ids));
  });
}

test.describe.serial("Document URL Routing", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account and create documents", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Route Doc A");
    await createDocument(sharedPage, "Route Doc B");
  });

  test("opening a document updates the URL", async () => {
    test.setTimeout(30_000);
    await openDocument(sharedPage, "Route Doc A");
    documentIdA = await currentDocumentId(sharedPage);

    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });
    await waitForPanel(sharedPage, documentIdA);
  });

  test("focused tile changes update the URL", async () => {
    test.setTimeout(45_000);

    const menu = await openContextMenu(sharedPage, "Route Doc B");
    await menu.locator("button", { hasText: "Add to Tile" }).click();

    await expect
      .poll(async () => (await openDocumentIds(sharedPage)).length, {
        timeout: 10_000,
        message: "second tiled document did not open",
      })
      .toBeGreaterThan(1);

    const openIds = await openDocumentIds(sharedPage);
    documentIdB = openIds.find((id) => id !== documentIdA)!;
    expect(documentIdB).toBeTruthy();
    await waitForPanel(sharedPage, documentIdB);
    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdB), { timeout: 10_000 });

    await sharedPage.locator(`[data-panel-id^="${documentIdA}:"]`).first().click();
    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });

    await sharedPage.locator(`[data-panel-id^="${documentIdB}:"]`).first().click();
    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdB), { timeout: 10_000 });
  });

  test("direct document URL opens the target document", async () => {
    test.setTimeout(60_000);

    await sharedPage.goto(`/document/${documentIdA}`, { waitUntil: "domcontentloaded" });
    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });
    await waitForPanel(sharedPage, documentIdA);
  });

  test("document route survives reload", async () => {
    test.setTimeout(60_000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });
    await waitForPanel(sharedPage, documentIdA);
  });
});
