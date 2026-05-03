import { expect, test, type Page, type Request, type Response } from "@playwright/test";
import {
  createDocument,
  createFolder,
  createWorkspace,
  currentWorkspaceId,
  registerAccount,
  waitForWorkspaceReady,
} from "./helpers";

async function createShareLinkFromUi(page: Page, title: string): Promise<string> {
  await page.locator("aside").getByRole("button", { name: title }).first().click({
    button: "right",
  });
  const menu = page.getByRole("menu").last();
  await expect(menu).toBeVisible({ timeout: 5_000 });
  await menu.getByRole("menuitem", { name: "Share" }).click();

  const dialog = page.locator('[role="dialog"]');
  await expect(dialog.getByText("Share Access")).toBeVisible({
    timeout: 10_000,
  });
  await dialog.getByRole("button", { name: "Create new link" }).click();
  await dialog.getByRole("button", { name: "Create Link" }).click();

  const input = dialog.locator("input[readonly]");
  await expect(input).toHaveValue(/\/share\/[^/]+$/, { timeout: 60_000 });
  const link = await input.inputValue();
  await page.keyboard.press("Escape");

  return link;
}

async function selectSidebarRow(page: Page, title: string): Promise<void> {
  const row = page.locator("aside").getByText(title, { exact: true }).first();
  await expect(row).toBeVisible({ timeout: 20_000 });
  await row.click();
}

async function selectLastSidebarRow(page: Page, title: string): Promise<void> {
  const row = page.locator("aside").getByText(title, { exact: true }).last();
  await expect(row).toBeVisible({ timeout: 20_000 });
  await row.click();
}

async function openLastSidebarContextMenu(page: Page, title: string) {
  const row = page.locator("aside").getByRole("button", { name: title }).last();
  await expect(row).toBeVisible({ timeout: 20_000 });
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await row.click({ button: "right", force: true });
    const menu = page.getByRole("menu").last();
    if (await menu.isVisible({ timeout: 2_000 }).catch(() => false)) {
      return menu;
    }
    await page.keyboard.press("Escape").catch(() => {});
    await page.waitForTimeout(250);
  }
  const menu = page.getByRole("menu").last();
  await expect(menu).toBeVisible({ timeout: 5_000 });
  return menu;
}

async function clickLastSidebarContextMenuItem(
  page: Page,
  title: string,
  itemName: string,
): Promise<void> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const menu = await openLastSidebarContextMenu(page, title);
      const item = menu.getByRole("menuitem", { name: itemName });
      await expect(item).toBeVisible({ timeout: 5_000 });
      await item.click();
      return;
    } catch (err) {
      lastError = err;
      await page.keyboard.press("Escape").catch(() => {});
      await page.waitForTimeout(500);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`failed to click ${itemName}`);
}

async function waitForMountedEditor(page: Page, message: string): Promise<void> {
  await expect
    .poll(
      async () =>
        page.evaluate(() => ({
          hasEditor: !!document.querySelector(".cm-content, .ProseMirror"),
          loading: document.body.textContent?.includes("Loading") ?? false,
          failedToLoad: document.body.textContent?.includes("Failed to load document") ?? false,
        })),
      {
        timeout: 90_000,
        message,
      },
    )
    .toMatchObject({
      hasEditor: true,
      failedToLoad: false,
    });
}

function collectPageDiagnostics(page: Page): {
  messages: string[];
  stop: () => void;
} {
  const messages: string[] = [];
  const consoleHandler = (msg: { type: () => string; text: () => string }) => {
    const text = msg.text();
    if (
      msg.type() === "error" ||
      text.includes("[ws]") ||
      text.includes("[PoP]") ||
      text.includes("DocumentSyncError")
    ) {
      messages.push(`console:${msg.type()}: ${text}`);
    }
  };
  const requestFailedHandler = (request: Request) => {
    const url = request.url();
    if (url.includes("/api/") || url.includes("/socket/")) {
      messages.push(`requestfailed: ${request.method()} ${url} ${request.failure()?.errorText}`);
    }
  };
  const responseHandler = (response: Response) => {
    const url = response.url();
    if ((url.includes("/api/") || url.includes("/socket/")) && response.status() >= 400) {
      messages.push(`response:${response.status()}: ${response.request().method()} ${url}`);
    }
  };

  page.on("console", consoleHandler);
  page.on("requestfailed", requestFailedHandler);
  page.on("response", responseHandler);

  return {
    messages,
    stop: () => {
      page.off("console", consoleHandler);
      page.off("requestfailed", requestFailedHandler);
      page.off("response", responseHandler);
    },
  };
}

async function createFolderMount(page: Page, args: {
  workspaceId: string;
  shareSlug: string;
  folderToken: string;
}): Promise<void> {
  await page.evaluate(async ({ workspaceId, shareSlug, folderToken }) => {
    const response = await fetch("/api/mounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        workspace_id: workspaceId,
        share_slug: shareSlug,
        target_kind: "folder",
        target_token: folderToken,
        parent_id: null,
      }),
    });
    if (!response.ok && response.status !== 409) {
      throw new Error(`failed to create mount: ${response.status} ${await response.text()}`);
    }
  }, args);
}

test("shared folder sidebar keeps the root while expanding nested folders", async ({ page }) => {
  test.setTimeout(180_000);

  await registerAccount(page);

  await createFolder(page, "Shared Root");
  await selectSidebarRow(page, "Shared Root");
  await createFolder(page, "Nested Shared Folder");
  await selectSidebarRow(page, "Nested Shared Folder");
  await createDocument(page, "Nested Shared Doc");

  const shareLink = await createShareLinkFromUi(page, "Shared Root");

  await page.goto(shareLink, { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/share\/f\/[^/]+$/, { timeout: 30_000 });
  const rootFolderUrl = page.url();

  await selectSidebarRow(page, "Nested Shared Folder");

  await expect(page).toHaveURL(rootFolderUrl);
  await expect(page.locator("aside").getByText("Shared Root", { exact: true })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.locator("aside").getByText("Nested Shared Doc", { exact: true })).toBeVisible({
    timeout: 20_000,
  });
});

test("saved folder share mount opens a nested child document from the sidebar", async ({ page }) => {
  test.setTimeout(180_000);
  const diagnostics = collectPageDiagnostics(page);

  try {
    await registerAccount(page);

    await createFolder(page, "Source Bundle");
    await selectSidebarRow(page, "Source Bundle");
    await createFolder(page, "Nested Folder");
    await selectSidebarRow(page, "Nested Folder");
    await createDocument(page, "Nested Mounted Doc");

    const shareLink = await createShareLinkFromUi(page, "Source Bundle");

    await createWorkspace(page, "Mount Target");
    const mountWorkspaceId = await currentWorkspaceId(page);
    await page.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(page).toHaveURL(/\/share\/f\/[^/]+$/, { timeout: 30_000 });
    const shareUrl = new URL(shareLink);
    const shareSlug = shareUrl.pathname.split("/").at(-1);
    const folderToken = new URL(page.url()).pathname.split("/").at(-1);
    if (!shareSlug || !folderToken) {
      throw new Error(`failed to resolve share mount tokens from ${shareLink} / ${page.url()}`);
    }
    await createFolderMount(page, {
      workspaceId: mountWorkspaceId,
      shareSlug,
      folderToken,
    });

    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await waitForWorkspaceReady(page);

    await expect(page.getByRole("button", { name: "Source Bundle view" })).toBeVisible({
      timeout: 20_000,
    });
    await page.getByRole("button", { name: "Source Bundle view" }).click();
    await expect
      .poll(
        async () => page.locator("aside").getByText("Nested Folder", { exact: true }).count(),
        {
          timeout: 20_000,
          message: "mounted folder children did not render in the sidebar",
        },
      )
      .toBeGreaterThan(0);

    await selectLastSidebarRow(page, "Nested Folder");
    await expect
      .poll(
        async () => page.locator("aside").getByText("Nested Mounted Doc", { exact: true }).count(),
        {
          timeout: 20_000,
          message: "mounted nested document did not render in the sidebar",
        },
      )
      .toBeGreaterThan(0);

    await selectLastSidebarRow(page, "Nested Mounted Doc");
    await expect(page).toHaveURL(/\/mounts\/[^?]+\?share=[^&]+$/, { timeout: 20_000 });
    await expect(page.getByRole("button", { name: "Source Bundle view" })).toBeVisible({
      timeout: 20_000,
    });
    await expect
      .poll(
        async () => page.locator("aside").getByText("Nested Folder", { exact: true }).count(),
        {
          timeout: 20_000,
          message: "mounted folder expansion was reset after opening a child document",
        },
      )
      .toBeGreaterThan(0);
    await expect
      .poll(
        async () => page.locator("aside").getByText("Nested Mounted Doc", { exact: true }).count(),
        {
          timeout: 20_000,
          message: "mounted nested document row disappeared after opening",
        },
      )
      .toBeGreaterThan(0);
    await expect
      .poll(
        async () => page.evaluate(() => document.querySelectorAll("[data-panel-id]").length),
        {
          timeout: 20_000,
          message: "mounted child document did not open in the workspace",
        },
      )
      .toBeGreaterThan(0);
    await waitForMountedEditor(page, "mounted child document editor did not finish loading");

    const panelCountBeforeTile = await page.evaluate(
      () => document.querySelectorAll("[data-panel-id]").length,
    );
    await clickLastSidebarContextMenuItem(page, "Nested Mounted Doc", "Add to Tile");
    await expect
      .poll(
        async () => page.evaluate(() => document.querySelectorAll("[data-panel-id]").length),
        {
          timeout: 20_000,
          message: "mounted child document was not added as a tile",
        },
      )
      .toBeGreaterThan(panelCountBeforeTile);
  } catch (err) {
    console.log(["share mount diagnostics:", ...diagnostics.messages].join("\n"));
    throw err;
  } finally {
    diagnostics.stop();
  }
});
