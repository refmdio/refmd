import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  createFolder,
  openContextMenu,
} from "../../support/documents";
import { E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;
const sidebarMutationTimeout = 60_000;

test.describe.serial("Document & Folder Management", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    await registerAccount(sharedPage);
  });

  test("manages documents and folders from creation through cleanup", async () => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("new document button opens dialog", async () => {
      await sharedPage.locator('[title="New Document"]').click();
      await expect(
        sharedPage.locator('input[placeholder="Document title"]'),
      ).toBeVisible({ timeout: 5_000 });
      await sharedPage.getByText("Cancel", { exact: true }).click();
      await expect(sharedPage.locator('input[placeholder="Document title"]')).not.toBeVisible({
        timeout: 5_000,
      });
    });

    await test.step("create and open documents", async () => {
      await createDocument(sharedPage, "Test Doc");
      await sharedPage.locator("aside").getByText("Test Doc").click();
      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 15_000 });

      await createDocument(sharedPage, "Second Doc");
      await expect(sharedPage.locator("aside").getByText("Test Doc")).toBeVisible();
      await expect(sharedPage.locator("aside").getByText("Second Doc")).toBeVisible();
    });

    await test.step("rename a document via context menu", async () => {
      const menu = await openContextMenu(sharedPage, "Second Doc");
      await menu.getByRole("menuitem", { name: "Rename" }).click();

      const dialog = sharedPage.locator('[role="dialog"]');
      await dialog.waitFor({ state: "visible", timeout: 5_000 });
      await dialog.locator("input").fill("Renamed Doc");
      await dialog.locator('button[type="submit"]').click();

      await expect(sharedPage.locator("aside").getByText("Renamed Doc")).toBeVisible({
        timeout: 30_000,
      });
      await expect(
        sharedPage.locator("aside").getByText("Second Doc"),
      ).not.toBeVisible({ timeout: 5_000 });
    });

    await test.step("archive and unarchive the renamed document", async () => {
      let menu = await openContextMenu(sharedPage, "Renamed Doc");
      await menu.getByRole("menuitem", { name: "Archive" }).click();
      await expect(sharedPage.locator("aside").getByText("Renamed Doc")).not.toBeVisible({
        timeout: sidebarMutationTimeout,
      });

      await expect(sharedPage.locator("aside").getByText("Archive")).toBeVisible({
        timeout: sidebarMutationTimeout,
      });
      await sharedPage.locator("aside").getByText("Archive").click();
      await expect(sharedPage.locator("aside").getByText("Renamed Doc")).toBeVisible({
        timeout: sidebarMutationTimeout,
      });

      menu = await openContextMenu(sharedPage, "Renamed Doc");
      await menu.getByRole("menuitem", { name: "Unarchive" }).click();

      await expect(
        sharedPage.locator("aside").getByText("Renamed Doc"),
      ).toBeVisible({ timeout: sidebarMutationTimeout });
    });

    await test.step("delete a document with confirmation", async () => {
      await createDocument(sharedPage, "Delete Me");

      const menu = await openContextMenu(sharedPage, "Delete Me");
      await menu.getByRole("menuitem", { name: "Delete" }).click();
      await expect(sharedPage.locator('[role="alertdialog"], [role="dialog"]')).toBeVisible({
        timeout: 5_000,
      });

      await sharedPage
        .locator('[role="alertdialog"], [role="dialog"]')
        .getByRole("button", { name: "Delete" })
        .click();

      await expect(
        sharedPage.locator("aside").getByText("Delete Me"),
      ).not.toBeVisible({ timeout: sidebarMutationTimeout });
    });

    await test.step("create, rename, and use a folder", async () => {
      await createFolder(sharedPage, "Test Folder");

      const renameMenu = await openContextMenu(sharedPage, "Test Folder");
      await renameMenu.getByRole("menuitem", { name: "Rename" }).click();

      const dialog = sharedPage.locator('[role="dialog"]');
      await dialog.waitFor({ state: "visible", timeout: 5_000 });
      await dialog.locator("input").fill("My Folder");
      await dialog.locator('button[type="submit"]').click();

      await expect(
        sharedPage.locator("aside").getByText("My Folder"),
      ).toBeVisible({ timeout: sidebarMutationTimeout });

      const moveMenu = await openContextMenu(sharedPage, "Renamed Doc");
      await moveMenu.getByRole("menuitem", { name: "Move" }).click();
      await expect(sharedPage.locator('[role="dialog"]')).toBeVisible({ timeout: 5_000 });

      await sharedPage.getByRole("button", { name: "My Folder" }).click();
      await sharedPage.locator('[role="dialog"]').getByRole("button", { name: "Move" }).click();
      await expect(sharedPage.locator('[role="dialog"]')).not.toBeVisible({
        timeout: sidebarMutationTimeout,
      });
    });

    await test.step("delete an empty folder via context menu", async () => {
      await createFolder(sharedPage, "Empty Folder");

      const menu = await openContextMenu(sharedPage, "Empty Folder");
      await menu.getByRole("menuitem", { name: "Delete" }).click();
      await expect(sharedPage.locator('[role="alertdialog"], [role="dialog"]')).toBeVisible({
        timeout: 5_000,
      });

      await sharedPage
        .locator('[role="alertdialog"], [role="dialog"]')
        .getByRole("button", { name: "Delete" })
        .click();

      await expect(
        sharedPage.locator("aside").getByText("Empty Folder"),
      ).not.toBeVisible({ timeout: sidebarMutationTimeout });
    });
  });
});
