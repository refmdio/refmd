import { expect, test, type Page } from "@playwright/test";
import {
  createDocument,
  createFolder,
  createWorkspace,
  openDocument,
  registerAccount,
  switchWorkspace,
  newE2EContext,
} from "./helpers";

let sharedPage: Page;
let defaultWorkspaceName: string;
let secondWorkspaceName = "Routing Workspace Two";
let defaultDocumentId: string;
let secondWorkspaceDocumentId: string;

function documentRouteRegex(documentId: string): RegExp {
  return new RegExp(`/document/${documentId}$`);
}

test.describe.serial("Document Routing Edge Cases", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: create documents, folder, and second workspace", async () => {
    test.setTimeout(240_000);

    await registerAccount(sharedPage);
    defaultWorkspaceName =
      (await sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]').textContent())?.trim() ??
      "";

    await createDocument(sharedPage, "Routing Edge Default Doc");
    await openDocument(sharedPage, "Routing Edge Default Doc");
    defaultDocumentId = new URL(sharedPage.url()).pathname.split("/").at(-1) ?? "";

    await createFolder(sharedPage, "Routing Edge Folder");
    await sharedPage.locator("aside").getByText("Routing Edge Folder").click();
    expect(defaultDocumentId).toBeTruthy();

    await createWorkspace(sharedPage, secondWorkspaceName);

    await createDocument(sharedPage, "Routing Edge Second Doc");
    await openDocument(sharedPage, "Routing Edge Second Doc");
    secondWorkspaceDocumentId = new URL(sharedPage.url()).pathname.split("/").at(-1) ?? "";
    expect(secondWorkspaceDocumentId).toBeTruthy();
  });

  test("direct document route switches workspace when the document belongs elsewhere", async () => {
    test.setTimeout(90_000);

    await switchWorkspace(sharedPage, defaultWorkspaceName);
    await expect(
      sharedPage.locator("aside").getByText("Routing Edge Default Doc"),
    ).toBeVisible({ timeout: 10_000 });
    await expect(
      sharedPage.locator("aside").getByText("Routing Edge Second Doc"),
    ).not.toBeVisible({ timeout: 5_000 });

    await sharedPage.goto(`/document/${secondWorkspaceDocumentId}`, {
      waitUntil: "domcontentloaded",
    });

    await expect(sharedPage).toHaveURL(documentRouteRegex(secondWorkspaceDocumentId), {
      timeout: 10_000,
    });
    await expect(sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]')).toContainText(
      secondWorkspaceName,
    );
    await expect(sharedPage.locator("aside").getByText("Routing Edge Second Doc")).toBeVisible({
      timeout: 10_000,
    });
  });

});
