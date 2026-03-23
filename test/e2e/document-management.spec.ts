import { test, expect, type Page } from "@playwright/test";
import {
  registerAccount,
  createDocument,
  createFolder,
  openContextMenu,
} from "./helpers";

let sharedPage: Page;

test.describe.serial("Document & Folder Management", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account", async () => {
    test.setTimeout(180_000);
    await registerAccount(sharedPage);
  });

  // ── Document Creation ──────────────────────────────────────

  // DOC-01
  test("new document button opens dialog", async () => {
    test.setTimeout(10_000);
    await sharedPage.locator('[title="New Document"]').click();
    await sharedPage.waitForTimeout(1000);
    await expect(
      sharedPage.locator('input[placeholder="Document title"]'),
    ).toBeVisible({ timeout: 5_000 });
    await sharedPage.getByText("Cancel", { exact: true }).click();
    await sharedPage.waitForTimeout(500);
  });

  // DOC-02
  test("creates a document visible in sidebar", async () => {
    test.setTimeout(30_000);
    await createDocument(sharedPage, "Test Doc");
  });

  // DOC-03
  test("opens document and shows CodeMirror editor", async () => {
    test.setTimeout(30_000);
    await sharedPage.locator("aside").getByText("Test Doc").click();
    await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 15_000 });
  });

  // DOC-04
  test("creates multiple documents visible in sidebar", async () => {
    test.setTimeout(30_000);
    await createDocument(sharedPage, "Second Doc");
    await expect(sharedPage.locator("aside").getByText("Test Doc")).toBeVisible();
    await expect(sharedPage.locator("aside").getByText("Second Doc")).toBeVisible();
  });

  // ── Document Rename ────────────────────────────────────────

  // RENAME-01 + RENAME-02 + RENAME-03
  test("renames a document via context menu", async () => {
    test.setTimeout(30_000);
    const menu = await openContextMenu(sharedPage, "Second Doc");
    await menu.locator("button", { hasText: "Rename" }).click();
    await sharedPage.waitForTimeout(1000);

    const dialog = sharedPage.locator('[role="dialog"]');
    await dialog.waitFor({ state: "visible", timeout: 5_000 });
    const input = dialog.locator("input");

    await input.fill("Renamed Doc");
    await sharedPage.waitForTimeout(500);

    await dialog.locator('button[type="submit"]').click();
    await sharedPage.waitForTimeout(3000);

    await expect(sharedPage.locator("aside").getByText("Renamed Doc")).toBeVisible({
      timeout: 10_000,
    });
    await expect(
      sharedPage.locator("aside").getByText("Second Doc"),
    ).not.toBeVisible({ timeout: 5_000 });
  });

  // ── Document Archive / Unarchive ───────────────────────────

  // ARCHIVE-01
  test("archive removes document from main tree", async () => {
    test.setTimeout(30_000);
    const menu = await openContextMenu(sharedPage, "Renamed Doc");
    await menu.locator("button", { hasText: "Archive" }).click();
    await sharedPage.waitForTimeout(2000);
  });

  // ARCHIVE-02
  test("archive section appears in sidebar", async () => {
    test.setTimeout(10_000);
    await expect(sharedPage.locator("aside").getByText("Archive")).toBeVisible({
      timeout: 10_000,
    });
  });

  // ARCHIVE-03
  test("archived document is listed in archive section", async () => {
    test.setTimeout(10_000);
    await sharedPage.locator("aside").getByText("Archive").click();
    await sharedPage.waitForTimeout(1000);
    await expect(sharedPage.locator("aside").getByText("Renamed Doc")).toBeVisible({
      timeout: 5_000,
    });
  });

  // ARCHIVE-04
  test("unarchive restores document to main tree", async () => {
    test.setTimeout(30_000);
    const menu = await openContextMenu(sharedPage, "Renamed Doc");
    await menu.locator("button", { hasText: "Unarchive" }).click();
    await sharedPage.waitForTimeout(2000);

    await expect(
      sharedPage.locator("aside").getByText("Renamed Doc"),
    ).toBeVisible({ timeout: 10_000 });
  });

  // ── Document Deletion ──────────────────────────────────────

  // DEL-01 + DEL-02
  test("deletes a document with confirmation", async () => {
    test.setTimeout(30_000);
    await createDocument(sharedPage, "Delete Me");

    const menu = await openContextMenu(sharedPage, "Delete Me");
    await menu.locator("button", { hasText: "Delete" }).click();
    await sharedPage.waitForTimeout(500);

    await sharedPage
      .locator('[role="alertdialog"], [role="dialog"]')
      .getByRole("button", { name: "Delete" })
      .click();
    await sharedPage.waitForTimeout(2000);

    await expect(
      sharedPage.locator("aside").getByText("Delete Me"),
    ).not.toBeVisible({ timeout: 10_000 });
  });

  // ── Folder Management ──────────────────────────────────────

  // FOLDER-01 + FOLDER-02
  test("creates a folder visible in sidebar", async () => {
    test.setTimeout(30_000);
    await createFolder(sharedPage, "Test Folder");
  });

  // FOLDER-03
  test("renames a folder via context menu", async () => {
    test.setTimeout(30_000);
    const menu = await openContextMenu(sharedPage, "Test Folder");
    await menu.locator("button", { hasText: "Rename" }).click();
    await sharedPage.waitForTimeout(1000);

    const dialog = sharedPage.locator('[role="dialog"]');
    await dialog.waitFor({ state: "visible", timeout: 5_000 });
    const input = dialog.locator("input");

    await input.fill("My Folder");
    await sharedPage.waitForTimeout(500);
    await dialog.locator('button[type="submit"]').click();
    await sharedPage.waitForTimeout(3000);

    await expect(
      sharedPage.locator("aside").getByText("My Folder"),
    ).toBeVisible({ timeout: 10_000 });
  });

  // FOLDER-04
  test("moves a document into a folder via context menu", async () => {
    test.setTimeout(30_000);
    const menu = await openContextMenu(sharedPage, "Renamed Doc");
    await menu.locator("button", { hasText: "Move" }).click();
    await sharedPage.waitForTimeout(1000);

    await sharedPage.getByRole("button", { name: "My Folder" }).click();
    await sharedPage.locator('[role="dialog"]').getByRole("button", { name: "Move" }).click();
    await sharedPage.waitForTimeout(2000);
  });

  // FOLDER-05
  test("deletes an empty folder via context menu", async () => {
    test.setTimeout(30_000);
    await createFolder(sharedPage, "Empty Folder");

    const menu = await openContextMenu(sharedPage, "Empty Folder");
    await menu.locator("button", { hasText: "Delete" }).click();
    await sharedPage.waitForTimeout(500);

    await sharedPage
      .locator('[role="alertdialog"], [role="dialog"]')
      .getByRole("button", { name: "Delete" })
      .click();
    await sharedPage.waitForTimeout(2000);

    await expect(
      sharedPage.locator("aside").getByText("Empty Folder"),
    ).not.toBeVisible({ timeout: 10_000 });
  });
});
