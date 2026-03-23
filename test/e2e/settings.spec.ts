import { test, expect, type Page } from "@playwright/test";
import { registerAccount, openSettings, selectSettingsTab } from "./helpers";

let sharedPage: Page;
let email: string;

test.describe.serial("Settings Dialog", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await browser.newContext({ bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test("setup: register account", async () => {
    test.setTimeout(180_000);
    email = await registerAccount(sharedPage);
  });

  // SET-01
  test("opens settings dialog with tab list", async () => {
    test.setTimeout(10_000);
    await openSettings(sharedPage);

    await expect(
      sharedPage.getByRole("tablist", { name: "Settings" }),
    ).toBeVisible({ timeout: 5_000 });
  });

  // SET-02
  test("About tab is accessible", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "About");

    await expect(
      sharedPage.getByRole("tab", { name: "About", selected: true }),
    ).toBeVisible({ timeout: 5_000 });
  });

  // SET-03
  test("Security tab shows current device", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Security");

    await expect(sharedPage.getByText("Devices").first()).toBeVisible({ timeout: 5_000 });
    await expect(sharedPage.getByText("(this device)")).toBeVisible({
      timeout: 5_000,
    });
  });

  // SET-04
  test("Workspace tab shows Members section", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Workspace");

    await expect(sharedPage.getByText("Members").first()).toBeVisible({ timeout: 5_000 });
  });

  // SET-05
  test("Editor tab shows Default Editor Mode setting", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Editor");

    await expect(sharedPage.getByText("Default Editor Mode")).toBeVisible({
      timeout: 5_000,
    });
  });

  // SET-06
  test("Account tab shows user email", async () => {
    test.setTimeout(10_000);
    await selectSettingsTab(sharedPage, "Account");

    await expect(sharedPage.getByText(email)).toBeVisible({ timeout: 5_000 });
  });

  // SET-07
  test("Account tab has logout button", async () => {
    test.setTimeout(10_000);

    await expect(
      sharedPage.getByRole("button", { name: "Log out" }),
    ).toBeVisible({ timeout: 5_000 });

    // Close settings
    await sharedPage.keyboard.press("Escape");
    await sharedPage.waitForTimeout(500);
  });
});
