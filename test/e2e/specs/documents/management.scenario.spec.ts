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

async function readAppDocument(
  page: Page,
  title: string,
): Promise<{ id: string; parentId: string | null; title: string } | null> {
  return page.evaluate((targetTitle) => {
    const win = window as Window & {
      __REFMD_APP_INSTANCE__?: {
        documents?: {
          getDocumentList?: () => Array<{
            id: string;
            parentId: string | null;
            title: string;
          }>;
        };
      };
    };
    return (
      win.__REFMD_APP_INSTANCE__?.documents
        ?.getDocumentList?.()
        .find((doc) => doc.title === targetTitle) ?? null
    );
  }, title);
}

async function expectDocumentInsideFolder(
  page: Page,
  documentTitle: string,
  folderTitle: string,
): Promise<void> {
  await expect
    .poll(
      async () => {
        const [document, folder] = await Promise.all([
          readAppDocument(page, documentTitle),
          readAppDocument(page, folderTitle),
        ]);
        return Boolean(document && folder && document.parentId === folder.id);
      },
      {
        timeout: sidebarMutationTimeout,
        message: `${documentTitle} was not moved inside ${folderTitle}`,
      },
    )
    .toBe(true);
}

async function dragSidebarItemInsideFolder(
  page: Page,
  documentTitle: string,
  folderTitle: string,
): Promise<void> {
  const sidebar = page.locator("aside");
  const source = sidebar.getByRole("button", { name: documentTitle }).first();
  const target = sidebar.getByRole("button", { name: folderTitle }).first();
  await expect(source).toBeVisible({ timeout: sidebarMutationTimeout });
  await expect(target).toBeVisible({ timeout: sidebarMutationTimeout });

  const targetBox = await target.boundingBox();
  expect(targetBox).toBeTruthy();

  await source.dragTo(target, {
    targetPosition: {
      x: Math.max(8, Math.min(targetBox!.width - 8, targetBox!.width / 2)),
      y: Math.max(4, Math.min(targetBox!.height - 4, targetBox!.height / 2)),
    },
  });
}

async function expectSidebarIndentGreater(
  page: Page,
  childTitle: string,
  parentTitle: string,
): Promise<void> {
  const sidebar = page.locator("aside");
  const child = sidebar.getByRole("button", { name: childTitle }).first();
  const parent = sidebar.getByRole("button", { name: parentTitle }).first();
  await expect(child).toBeVisible({ timeout: sidebarMutationTimeout });
  await expect(parent).toBeVisible({ timeout: sidebarMutationTimeout });

  const [childPadding, parentPadding] = await Promise.all([
    child.evaluate((el) => Number.parseFloat(getComputedStyle(el).paddingLeft)),
    parent.evaluate((el) => Number.parseFloat(getComputedStyle(el).paddingLeft)),
  ]);
  expect(childPadding).toBeGreaterThan(parentPadding);
}

async function reloadAndExpectSidebarItems(page: Page, titles: string[]): Promise<void> {
  await page.reload({ waitUntil: "domcontentloaded" });
  for (const title of titles) {
    await expect(page.locator("aside").getByRole("button", { name: title }).first()).toBeVisible({
      timeout: sidebarMutationTimeout,
    });
  }
}

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

    await test.step("drag and drop moves a document into a folder hierarchy", async () => {
      await createFolder(sharedPage, "Dnd Folder");
      await createDocument(sharedPage, "Dnd Document");
      await createFolder(sharedPage, "Nested Dnd Folder");

      await dragSidebarItemInsideFolder(sharedPage, "Dnd Document", "Dnd Folder");
      await expectDocumentInsideFolder(sharedPage, "Dnd Document", "Dnd Folder");
      await expectSidebarIndentGreater(sharedPage, "Dnd Document", "Dnd Folder");

      await dragSidebarItemInsideFolder(sharedPage, "Nested Dnd Folder", "Dnd Folder");
      await expectDocumentInsideFolder(sharedPage, "Nested Dnd Folder", "Dnd Folder");
      await expectSidebarIndentGreater(sharedPage, "Nested Dnd Folder", "Dnd Folder");

      await reloadAndExpectSidebarItems(sharedPage, [
        "Dnd Folder",
        "Dnd Document",
        "Nested Dnd Folder",
      ]);
      await expectDocumentInsideFolder(sharedPage, "Dnd Document", "Dnd Folder");
      await expectDocumentInsideFolder(sharedPage, "Nested Dnd Folder", "Dnd Folder");
      await expectSidebarIndentGreater(sharedPage, "Dnd Document", "Dnd Folder");
      await expectSidebarIndentGreater(sharedPage, "Nested Dnd Folder", "Dnd Folder");
    });
  });
});
