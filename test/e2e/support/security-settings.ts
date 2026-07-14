import { expect, type Locator, type Page } from "@playwright/test";

export async function openSecuritySettings(page: Page): Promise<void> {
  await page.getByLabel("Settings").first().click({ timeout: 60_000 });
  await page.getByRole("tab", { name: "Security" }).click({ timeout: 60_000 });
  await expect(page.getByText("Devices").first()).toBeVisible({ timeout: 60_000 });
}

export async function renameCurrentDevice(page: Page, name: string): Promise<void> {
  await openSecuritySettings(page);
  const current = deviceRow(page.getByText("(this device)"));
  await current.getByTitle("Rename device").click({ timeout: 60_000 });
  const input = page.locator("input.h-7");
  await input.fill(name, { timeout: 60_000 });
  await input.press("Enter");
  await expect(deviceName(page, name)).toBeVisible({ timeout: 60_000 });
}

export function deviceRowByName(page: Page, name: string): Locator {
  return deviceRow(deviceName(page, name));
}

function deviceRow(locator: Locator): Locator {
  return locator.locator("xpath=ancestor::div[contains(@class,'justify-between')][1]");
}

function deviceName(page: Page, name: string): Locator {
  return page.locator("div.font-medium").filter({ hasText: name }).first();
}
