import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  openSettings,
  selectSettingsTab,
} from "../../support/settings";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("Community Plugins management surface is reachable from settings", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);
  const context = await newE2EContext(browser, { bypassCSP: true });
  const page = await context.newPage();

  await registerAccount(page);
  await openSettings(page);
  await selectSettingsTab(page, "Community Plugins");

  const dialog = page.locator('[role="dialog"]').filter({ hasText: "Community Plugins" });
  await expect(dialog.getByRole("heading", { name: "Community Plugins" })).toBeVisible({
    timeout: 5_000,
  });
  await expect(dialog.getByRole("heading", { name: "Add Plugin" })).toBeVisible({
    timeout: 5_000,
  });
  await expect(dialog.getByRole("button", { name: "URL" })).toBeVisible({ timeout: 5_000 });
  await expect(dialog.getByRole("button", { name: "Upload" })).toBeVisible({ timeout: 5_000 });
  await expect(dialog.getByRole("button", { name: "Personal" })).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Workspace" })).toHaveCount(0);
  await expect(dialog.locator("textarea")).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Review Plugin" })).toBeVisible({
    timeout: 5_000,
  });
  await expect(dialog.getByText("Create Candidate", { exact: true })).toHaveCount(0);
  await expect(dialog.getByText("Owner scope", { exact: true })).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Approve Package" })).toHaveCount(0);
  await expect(dialog.getByRole("heading", { name: "Packages" })).toHaveCount(0);
  await expect(dialog.getByRole("heading", { name: "Activations" })).toHaveCount(0);

  await context.close();
});
