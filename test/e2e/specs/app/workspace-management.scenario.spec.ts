import { test, expect, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { createDocument } from "../../support/documents";
import {
  openSettings,
  selectSettingsTab,
} from "../../support/settings";
import {
  createWorkspace,
  switchWorkspace,
  waitForWorkspaceReady,
} from "../../support/workspace";
import { E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

test.describe.serial("Workspace Management", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  // WS-01
  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    await registerAccount(sharedPage);
  });

  test("manages workspace creation, isolation, switching, and settings", async () => {
    test.setTimeout(E2E_TIMEOUTS.syncScenario);

    await test.step("create a document in the default workspace", async () => {
      await createDocument(sharedPage, "Default WS Doc");
    });

    await test.step("create and select a new workspace", async () => {
      await createWorkspace(sharedPage, "Second Workspace");
      await expect(
        sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]'),
      ).toContainText("Second Workspace", { timeout: 20_000 });
    });

    await test.step("new workspace has an isolated empty document tree", async () => {
      await sharedPage.reload({ waitUntil: "domcontentloaded" });

      await waitForWorkspaceReady(sharedPage);
      await expect(
        sharedPage.locator('aside [data-slot="dropdown-menu-trigger"]'),
      ).toContainText("Second Workspace", { timeout: 20_000 });

      await expect(
        sharedPage.locator("aside").getByText("Default WS Doc"),
      ).not.toBeVisible({ timeout: 10_000 });
    });

    await test.step("create a document in the new workspace", async () => {
      await createDocument(sharedPage, "Second WS Doc");
    });

    await test.step("switch to the default workspace and see only its document", async () => {
      await switchWorkspace(sharedPage, "E2E User");

      await expect(
        sharedPage.locator("aside").getByText("Default WS Doc"),
      ).toBeVisible({ timeout: 90_000 });
      await expect(
        sharedPage.locator("aside").getByText("Second WS Doc"),
      ).not.toBeVisible({ timeout: 10_000 });
    });

    await test.step("switch to the new workspace and see only its document", async () => {
      await switchWorkspace(sharedPage, "Second Workspace");

      await expect(
        sharedPage.locator("aside").getByText("Second WS Doc"),
      ).toBeVisible({ timeout: 10_000 });
      await expect(
        sharedPage.locator("aside").getByText("Default WS Doc"),
      ).not.toBeVisible({ timeout: 5_000 });
    });

    await test.step("settings shows the selected workspace name", async () => {
      await openSettings(sharedPage);
      await selectSettingsTab(sharedPage, "Workspace");

      await expect(sharedPage.getByText("Second Workspace").first()).toBeVisible({
        timeout: 10_000,
      });

      await sharedPage.keyboard.press("Escape");
    });
  });
});
