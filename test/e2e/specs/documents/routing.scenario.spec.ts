import { test, expect, type Page, type Request } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openContextMenu,
  openDocument,
} from "../../support/documents";
import { E2E_TIMEOUTS } from "../../support/timeouts";

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

async function waitForTile(page: Page, documentId: string): Promise<void> {
  await expect
    .poll(
      async () => page.locator(`[data-panel-id^="${documentId}:"]`).count(),
      {
        timeout: 15_000,
        message: `workspace tile not mounted for ${documentId}`,
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

async function openTileIds(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll("[data-panel-id]"))
      .map((el) => el.getAttribute("data-panel-id") ?? "")
      .filter((panelId) => panelId.length > 0),
  );
}

async function closeTile(page: Page, tileId: string): Promise<void> {
  const tile = page.locator(`[data-panel-id="${tileId}"]`);

  await tile.click();
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
    .poll(async () => page.locator(`[data-panel-id="${tileId}"]`).count(), {
      timeout: 10_000,
      message: `tile did not close: ${tileId}`,
    })
    .toBe(0);
}

async function captureRequestPathsDuring(
  page: Page,
  action: () => Promise<void>,
): Promise<string[]> {
  const paths: string[] = [];
  const handler = (request: Request) => {
    paths.push(new URL(request.url()).pathname);
  };

  page.on("request", handler);
  try {
    await action();
  } finally {
    page.off("request", handler);
  }

  return paths;
}

function nonCriticalDocumentStartupPaths(paths: readonly string[]): string[] {
  return paths.filter(
    (path) =>
      path === "/health" ||
      path === "/api/devices/registrations" ||
      path === "/api/security/notifications" ||
      path.includes("/plugin-runtime"),
  );
}

test.describe.serial("Document URL Routing", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Route Doc A");
    await createDocument(sharedPage, "Route Doc B");
    await createDocument(sharedPage, "Route Doc C");
  });

  test("document route tracks opened, focused, reloaded, and closed tiles", async () => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("opening a document updates the URL", async () => {
      await openDocument(sharedPage, "Route Doc A");
      documentIdA = await currentDocumentId(sharedPage);

      await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });
      await waitForTile(sharedPage, documentIdA);
    });

    await test.step("focused tile changes update the URL", async () => {
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
      await waitForTile(sharedPage, documentIdB);
      await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdB), { timeout: 10_000 });

      await sharedPage.locator(`[data-panel-id^="${documentIdA}:"]`).first().click();
      await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });

      await sharedPage.locator(`[data-panel-id^="${documentIdB}:"]`).first().click();
      await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdB), { timeout: 10_000 });
    });

    await test.step("sidebar click replaces the tiled workspace", async () => {
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

    await test.step("direct document URL opens the target document", async () => {
      const requestPaths = await captureRequestPathsDuring(sharedPage, async () => {
        await sharedPage.goto(`/document/${documentIdA}`, { waitUntil: "domcontentloaded" });
        await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });
        await waitForTile(sharedPage, documentIdA);
      });

      expect(nonCriticalDocumentStartupPaths(requestPaths)).toEqual([]);
    });

    await test.step("document route survives reload", async () => {
      await sharedPage.reload({ waitUntil: "domcontentloaded" });
      await expect(sharedPage).toHaveURL(documentRouteRegex(documentIdA), { timeout: 10_000 });
      await waitForTile(sharedPage, documentIdA);
    });

    await test.step("closing the last open tile returns to dashboard", async () => {
      let tileIds = await openTileIds(sharedPage);
      while (tileIds.length > 0) {
        await closeTile(sharedPage, tileIds[0]);
        tileIds = await openTileIds(sharedPage);
      }

      await expect(sharedPage).toHaveURL(/\/dashboard$/, { timeout: 10_000 });
      await expect
        .poll(async () => sharedPage.locator("[data-panel-id]").count(), {
          timeout: 10_000,
          message: "workspace tiles remained open after closing the last tile",
        })
        .toBe(0);
    });
  });
});
