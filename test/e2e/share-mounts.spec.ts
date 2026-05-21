import { expect, test, type Page } from "@playwright/test";
import {
  createDocument,
  createFolder,
  createWorkspace,
  currentWorkspaceId,
  registerAccount,
  waitForWorkspaceReady,
} from "./helpers";

const SHARE_FOLDER_ROUTE_RE = /\/share\/f\/[^/#]+(?:#s=[A-Za-z0-9_-]{22})?$/;
const MOUNT_CHILD_RENDER_TIMEOUT_MS = 60_000;

async function createShareLinkFromUi(
  page: Page,
  title: string,
  permission: "view" | "edit" = "view",
): Promise<string> {
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
  if (permission === "edit") {
    await dialog.locator("#share-permission").click();
    const option = page
      .locator('[data-slot="select-content"] [data-slot="select-item"]')
      .filter({ hasText: "Edit" })
      .last();
    await expect(option).toBeVisible({ timeout: 5_000 });
    await option.click();
  }
  await dialog.getByRole("button", { name: "Create Link" }).click();

  const input = dialog.locator("input[readonly]");
  await expect(input).toHaveValue(/\/share\/[^/#]+#cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}$/, {
    timeout: 60_000,
  });
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

async function typeInVisibleMountedEditor(page: Page, text: string): Promise<void> {
  const editor = page.locator(".cm-content, .ProseMirror").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click({ force: true });
  await editor.evaluate((element) => {
    if (element instanceof HTMLElement) element.focus();
  });
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
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
  await expect(page).toHaveURL(SHARE_FOLDER_ROUTE_RE, {
    timeout: 30_000,
  });
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

  await registerAccount(page);

  await createFolder(page, "Source Bundle");
  await selectSidebarRow(page, "Source Bundle");
  await createFolder(page, "Nested Folder");
  await selectSidebarRow(page, "Nested Folder");
  await createDocument(page, "Nested Mounted Doc");

  const shareLink = await createShareLinkFromUi(page, "Source Bundle", "edit");

  const mountWorkspaceName = `Mount Target ${Date.now()}`;
  await createWorkspace(page, mountWorkspaceName);
  await currentWorkspaceId(page);
  await page.goto(shareLink, { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(SHARE_FOLDER_ROUTE_RE, {
    timeout: 30_000,
  });
  await page.getByRole("button", { name: "Choose workspace" }).first().click();
  await expect(page.getByRole("heading", { name: "Save to Workspace" })).toBeVisible({
    timeout: 20_000,
  });
  await page.getByRole("button", { name: mountWorkspaceName }).click();
  await expect(page.getByRole("button", { name: "Already saved" }).first()).toBeVisible({
    timeout: 20_000,
  });

  await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);

  const savedRootButton = page
    .getByRole("button", { name: "Source Bundle edit" })
    .or(page.getByRole("button", { name: "Shared folder edit" }));
  await expect(savedRootButton).toBeVisible({
    timeout: 20_000,
  });
  const rootBootstrapResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      /\/api\/mounts\/[^/]+\/folders\/[^/]+\/bootstrap$/.test(new URL(response.url()).pathname),
  );
  await savedRootButton.click();
  const rootBootstrap = await rootBootstrapResponse;
  const rootBootstrapBody = (await rootBootstrap.json()) as { entries?: unknown[]; error?: string };
  expect(rootBootstrap.ok(), JSON.stringify(rootBootstrapBody)).toBe(true);
  expect(
    Array.isArray(rootBootstrapBody.entries) ? rootBootstrapBody.entries.length : 0,
    JSON.stringify(rootBootstrapBody),
  ).toBeGreaterThan(0);
  await expect
    .poll(
      async () => page.locator("aside").getByText("Nested Folder", { exact: true }).count(),
      {
        timeout: MOUNT_CHILD_RENDER_TIMEOUT_MS,
        message: "mounted folder children did not render in the sidebar",
      },
    )
    .toBeGreaterThan(0);

  await selectLastSidebarRow(page, "Nested Folder");
  await expect
    .poll(
      async () => page.locator("aside").getByText("Nested Mounted Doc", { exact: true }).count(),
      {
        timeout: MOUNT_CHILD_RENDER_TIMEOUT_MS,
        message: "mounted nested document did not render in the sidebar",
      },
    )
    .toBeGreaterThan(0);

  await selectLastSidebarRow(page, "Nested Mounted Doc");
  await expect(page).toHaveURL(/\/mounts\/[^?]+\?share=[^&]+$/, { timeout: 20_000 });
  await expect(savedRootButton).toBeVisible({
    timeout: 20_000,
  });
  await expect
    .poll(
      async () => page.locator("aside").getByText("Nested Folder", { exact: true }).count(),
      {
        timeout: MOUNT_CHILD_RENDER_TIMEOUT_MS,
        message: "mounted folder expansion was reset after opening a child document",
      },
    )
    .toBeGreaterThan(0);
  await expect
    .poll(
      async () => page.locator("aside").getByText("Nested Mounted Doc", { exact: true }).count(),
      {
        timeout: MOUNT_CHILD_RENDER_TIMEOUT_MS,
        message: "mounted nested document row disappeared after opening",
      },
    )
    .toBeGreaterThan(0);
  await expect
    .poll(async () => page.evaluate(() => document.querySelectorAll("[data-panel-id]").length), {
      timeout: 20_000,
      message: "mounted child document did not open in the workspace",
    })
    .toBeGreaterThan(0);
  await waitForMountedEditor(page, "mounted child document editor did not finish loading");

  const durableText = `Mounted durable edit ${Date.now()}`;
  await typeInVisibleMountedEditor(page, durableText);
  await expect(page.locator(".cm-content, .ProseMirror").first()).toContainText(durableText, {
    timeout: 20_000,
  });
  await page.waitForTimeout(3_000);
  await expect(page).toHaveURL(/\/mounts\/[^?]+\?share=[^&]+$/, { timeout: 20_000 });

  await page.reload({ waitUntil: "domcontentloaded" });
  await waitForWorkspaceReady(page);
  await expect(page).toHaveURL(/\/mounts\/[^?]+\?share=[^&]+$/, { timeout: 20_000 });
  await waitForMountedEditor(page, "mounted child document did not reopen after reload");
  await expect(page.locator(".cm-content, .ProseMirror").first()).toContainText(durableText, {
    timeout: 30_000,
  });
  if ((await page.locator("aside").getByText("Nested Mounted Doc", { exact: true }).count()) === 0) {
    await savedRootButton.click();
    await selectLastSidebarRow(page, "Nested Folder");
  }

  const panelCountBeforeTile = await page.evaluate(
    () => document.querySelectorAll("[data-panel-id]").length,
  );
  await clickLastSidebarContextMenuItem(page, "Nested Mounted Doc", "Add to Tile");
  await expect
    .poll(async () => page.evaluate(() => document.querySelectorAll("[data-panel-id]").length), {
      timeout: 20_000,
      message: "mounted child document was not added as a tile",
    })
    .toBeGreaterThan(panelCountBeforeTile);
});
