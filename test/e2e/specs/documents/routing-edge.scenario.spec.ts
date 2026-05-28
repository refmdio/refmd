import { expect, test, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  createFolder,
  openDocument,
} from "../../support/documents";
import {
  createWorkspace,
  switchWorkspace,
} from "../../support/workspace";
import { E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;
let defaultWorkspaceName: string;
let secondWorkspaceName = "Routing Workspace Two";
let defaultDocumentId: string;
let secondWorkspaceDocumentId: string;

const ROUTE_WORKSPACE_SWITCH_TIMEOUT_MS = 120_000;
const ROUTE_SIDEBAR_LOAD_TIMEOUT_MS = 180_000;

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

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.pluginInstall);

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
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

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
      timeout: 60_000,
    });
    await expect(sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]')).toContainText(
      secondWorkspaceName,
      { timeout: ROUTE_WORKSPACE_SWITCH_TIMEOUT_MS },
    );
    await expect(sharedPage.locator("aside").getByText("Loading", { exact: true })).toHaveCount(0, {
      timeout: ROUTE_SIDEBAR_LOAD_TIMEOUT_MS,
    });
    await expect(
      sharedPage.locator("aside").getByRole("button", { name: "Routing Edge Second Doc" }),
    ).toBeVisible({ timeout: ROUTE_SIDEBAR_LOAD_TIMEOUT_MS });
  });

});
