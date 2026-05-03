import { test, expect, type Page } from "@playwright/test";
import { createDocument, openContextMenu, openDocument, registerAccount,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;
let documentIdA: string;
let documentIdB: string;
let documentIdC: string;

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

async function openPanelIds(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll("[data-panel-id]"))
      .map((el) => el.getAttribute("data-panel-id") ?? "")
      .filter((panelId) => panelId.length > 0),
  );
}

async function closePanel(page: Page, panelId: string): Promise<void> {
  const panel = page.locator(`[data-panel-id="${panelId}"]`);

  await panel.click();
  await page.evaluate(() => {
    const app = (globalThis as { __REFMD_APP_INSTANCE__?: unknown }).__REFMD_APP_INSTANCE__ as
      | {
          workspace: {
            listCommands(): Array<{ id: string; callback?: () => void }>;
          };
        }
      | undefined;
    app?.workspace.listCommands().find((command) => command.id === "editor:close-panel")?.callback?.();
  });
  await expect
    .poll(async () => page.locator(`[data-panel-id="${panelId}"]`).count(), {
      timeout: 10_000,
      message: `panel did not close: ${panelId}`,
    })
    .toBe(0);
}

test.describe.serial("Document URL Routing", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account and create documents", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Route Doc A");
    await createDocument(sharedPage, "Route Doc B");
    await createDocument(sharedPage, "Route Doc C");
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
    await menu.getByRole("menuitem", { name: "Add to Tile" }).click();

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

  test("sidebar click replaces the tiled workspace", async () => {
    test.setTimeout(45_000);

    await openDocument(sharedPage, "Route Doc C");
    documentIdC = await currentDocumentId(sharedPage);

    await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdC), { timeout: 10_000 });
    await expect
      .poll(async () => openDocumentIds(sharedPage), {
        timeout: 10_000,
        message: "sidebar click did not replace the tiled workspace",
      })
      .toEqual([documentIdC]);
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

  test("closing the last open panel returns to dashboard", async () => {
    test.setTimeout(60_000);

    let panelIds = await openPanelIds(sharedPage);
    while (panelIds.length > 0) {
      await closePanel(sharedPage, panelIds[0]);
      panelIds = await openPanelIds(sharedPage);
    }

    await expect(sharedPage).toHaveURL(/\/dashboard$/, { timeout: 10_000 });
    await expect
      .poll(async () => sharedPage.locator("[data-panel-id]").count(), {
        timeout: 10_000,
        message: "document panels remained open after closing the last panel",
      })
      .toBe(0);
  });
});
