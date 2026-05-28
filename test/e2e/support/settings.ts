import { expect, type Page } from "@playwright/test";
import { E2E_DELAYS } from "./timeouts";
import { waitForWorkspaceReady } from "./workspace";

export async function openSettings(page: Page): Promise<void> {
  await waitForWorkspaceReady(page);
  const settingsDialog = page.locator('[role="dialog"]').filter({
    has: page.getByRole("heading", { name: "Settings" }),
  });
  if (await settingsDialog.isVisible({ timeout: 1_000 }).catch(() => false)) {
    return;
  }

  const settingsButton = page
    .getByRole("button", { name: "Settings" })
    .or(page.locator('button[aria-label="Settings"], button[title="Settings"]'))
    .first();
  if (!(await settingsButton.isVisible({ timeout: 5_000 }).catch(() => false))) {
    const loginForm = page.locator("#email");
    if (await loginForm.isVisible({ timeout: 2_000 }).catch(() => false)) {
      throw new Error("settings unavailable because session is not active");
    }
  }
  const visibleSettingsButton = page
    .getByRole("button", { name: "Settings" })
    .or(page.locator('button[aria-label="Settings"], button[title="Settings"]'))
    .first();
  await expect(visibleSettingsButton).toBeVisible({ timeout: 20_000 });
  await visibleSettingsButton.click({ timeout: 10_000 }).catch(async () => {
    await visibleSettingsButton.click({ timeout: 5_000, force: true });
  });
  await page.waitForTimeout(E2E_DELAYS.uiSettle);
}

export async function selectSettingsTab(page: Page, tabName: string): Promise<void> {
  const tab = page.getByRole("tab", { name: tabName });
  await tab.click({ timeout: 10_000 }).catch(async (clickError) => {
    await tab.click({ timeout: 5_000, force: true }).catch(async (forceClickError) => {
      const clicked = await page.evaluate((name) => {
        const tabs = Array.from(document.querySelectorAll<HTMLElement>('[role="tab"]'));
        const tabNode = tabs.find((node) => node.textContent?.trim().includes(name));
        tabNode?.click();
        return Boolean(tabNode);
      }, tabName);
      if (!clicked) {
        throw new Error(
          `Settings tab click failed for ${tabName}:\nnormal=${String(clickError)}\nforce=${String(
            forceClickError,
          )}`,
        );
      }
    });
  });
  await page.waitForTimeout(E2E_DELAYS.poll);
}

export async function expectToast(page: Page, message: string, timeout = 10_000): Promise<void> {
  await expect(page.locator('[data-sonner-toast]').getByText(message)).toBeVisible({
    timeout,
  });
}
