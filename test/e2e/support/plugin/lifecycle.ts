import {
  expect,
  type Page,
} from "@playwright/test";
import {
  openSettings,
  selectSettingsTab,
} from "../settings";
import { getSettingsDialog } from "./settings";

export async function secureLogout(page: Page): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Account");

  const settingsDialog = getSettingsDialog(page);
  await expect(settingsDialog.getByRole("heading", { name: "Account" })).toBeVisible({
    timeout: 30_000,
  });
  await settingsDialog.getByRole("button", { name: "Log out" }).click();

  const logoutDialog = page
    .locator('[role="dialog"]')
    .filter({
      has: page.getByRole("heading", { name: "Log out" }),
    })
    .last();
  await expect(logoutDialog.getByText("Keep credentials on this device")).toBeVisible({
    timeout: 10_000,
  });
  const keepCredentials = logoutDialog.locator("#keep-credentials");
  if (await keepCredentials.isChecked().catch(() => false)) {
    await logoutDialog.getByText("Keep credentials on this device").click();
  }
  await expect(keepCredentials).not.toBeChecked({ timeout: 5_000 });

  const confirmLogout = logoutDialog.getByRole("button", { name: "Log out" }).last();
  await expect(confirmLogout).toBeEnabled({ timeout: 10_000 });
  await confirmLogout.click({ timeout: 10_000 }).catch(async () => {
    await confirmLogout.click({ timeout: 10_000, force: true });
  });
  if (!(await page.waitForURL(/auth\/login|\/$/, { timeout: 10_000 }).then(() => true).catch(() => false))) {
    await confirmLogout.click({ timeout: 10_000, force: true }).catch(() => undefined);
  }
  if (!(await page.waitForURL(/auth\/login|\/$/, { timeout: 10_000 }).then(() => true).catch(() => false))) {
    await page
      .evaluate(() => {
        const dialogs = Array.from(document.querySelectorAll<HTMLElement>('[role="dialog"]'));
        const dialog = dialogs
          .reverse()
          .find((entry) => entry.textContent?.includes("Keep credentials on this device"));
        const button = Array.from(dialog?.querySelectorAll<HTMLButtonElement>("button") ?? [])
          .reverse()
          .find((entry) => entry.textContent?.trim() === "Log out" && !entry.disabled);
        button?.click();
        return Boolean(button);
      })
      .catch(() => false);
  }
  await expect(page).toHaveURL(/auth\/login|\/$/, { timeout: 30_000 });
  await expect(page.locator("#email")).toBeVisible({ timeout: 30_000 });
}
