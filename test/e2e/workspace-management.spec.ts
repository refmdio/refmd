import { test, expect, type Page } from "@playwright/test";
import {
  registerAccount,
  createDocument,
  openSettings,
  selectSettingsTab,
  waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;

test.describe.serial("Workspace Management", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  // WS-01
  test("setup: register account (default workspace exists)", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
  });

  // WS-02
  test("creates a document in default workspace", async () => {
    test.setTimeout(120_000);
    await createDocument(sharedPage, "Default WS Doc");
  });

  // WS-03
  test("creates a new workspace", async () => {
    test.setTimeout(120_000);

    // Open workspace dropdown (the trigger button with workspace name in aside)
    await sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]').click();
    await sharedPage.waitForTimeout(1000);

    // Wait for dropdown content and click New workspace
    await sharedPage.getByRole("menuitem", { name: "New workspace" }).click();
    await sharedPage.waitForTimeout(1000);

    await sharedPage.locator("#new-workspace-name").fill("Second Workspace");
    await sharedPage.waitForTimeout(500);

    // Click Create button within dialog context
    const dialog = sharedPage.locator('[role="dialog"]');
    await dialog.getByText("Create", { exact: true }).click();
    await expect(dialog).not.toBeVisible({ timeout: 90_000 });
    await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 10_000 });
    await waitForWorkspaceReady(sharedPage);
    await expect(
      sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]'),
    ).toContainText("Second Workspace", { timeout: 20_000 });
  });

  // WS-04
  test("new workspace has empty document tree", async () => {
    test.setTimeout(30_000);

    // Reload to ensure workspace state is fresh
    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await sharedPage.waitForTimeout(5000);

    await waitForWorkspaceReady(sharedPage);
    await expect(
      sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]'),
    ).toContainText("Second Workspace", { timeout: 20_000 });

    await expect(
      sharedPage.locator("aside").getByText("Default WS Doc"),
    ).not.toBeVisible({ timeout: 10_000 });
  });

  // WS-05
  test("creates a document in new workspace", async () => {
    test.setTimeout(120_000);
    await createDocument(sharedPage, "Second WS Doc");
  });

  // WS-06
  test("switches to default workspace and sees only its documents", async () => {
    test.setTimeout(30_000);

    await sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]').click();
    await sharedPage.waitForTimeout(1000);

    const workspaceItems = sharedPage.locator('[role="menuitem"]');
    await workspaceItems.first().waitFor({ state: "visible", timeout: 5_000 });
    await workspaceItems.first().click();
    await sharedPage.waitForTimeout(3000);

    await expect(
      sharedPage.locator("aside").getByText("Default WS Doc"),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      sharedPage.locator("aside").getByText("Second WS Doc"),
    ).not.toBeVisible({ timeout: 5_000 });
  });

  // WS-07
  test("switches to new workspace and sees only its documents", async () => {
    test.setTimeout(30_000);

    await sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]').click();
    await sharedPage.waitForTimeout(1000);

    await sharedPage.getByRole("menuitem", { name: "Second Workspace" }).click();
    await sharedPage.waitForTimeout(3000);

    await expect(
      sharedPage.locator("aside").getByText("Second WS Doc"),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      sharedPage.locator("aside").getByText("Default WS Doc"),
    ).not.toBeVisible({ timeout: 5_000 });
  });

  // WS-08
  test("settings shows workspace name", async () => {
    test.setTimeout(30_000);

    await openSettings(sharedPage);
    await selectSettingsTab(sharedPage, "Workspace");

    await expect(sharedPage.getByText("Second Workspace").first()).toBeVisible({
      timeout: 10_000,
    });

    await sharedPage.keyboard.press("Escape");
    await sharedPage.waitForTimeout(500);
  });
});
