import { expect, type Page } from "@playwright/test";

export const TEST_PASSWORD = "TestPassword123!";

export function testEmail(): string {
  return `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.com`;
}

/**
 * Register a new account. Returns email for subsequent login.
 * Ends on the dashboard page.
 */
export async function registerAccount(page: Page): Promise<string> {
  const email = testEmail();

  await page.goto("/auth/register");
  await page.waitForTimeout(2000);
  await page.locator("#name").fill("E2E User");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  // Argon2 key derivation + registration
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 120_000,
  });

  // Complete recovery key step
  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(1000);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(1000);
  await page.getByRole("button", { name: "Continue" }).click({ timeout: 10_000 });

  await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 });
  return email;
}

/**
 * Login with existing credentials. Ends on the dashboard page.
 */
export async function login(page: Page, email: string): Promise<void> {
  await page.goto("/auth/login");
  await page.waitForTimeout(2000);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page).toHaveURL(/dashboard/, { timeout: 120_000 });
}

/**
 * Create a new document with the given title. Assumes dashboard is visible.
 */
export async function createDocument(page: Page, title: string): Promise<void> {
  await page.waitForTimeout(2000);
  await page.locator("aside button").first().click();
  await page.waitForTimeout(2000);
  await page.locator('input[placeholder="Document title"]').fill(title);
  await page.getByText("Create", { exact: true }).click();

  await expect(page.locator("aside").getByText(title)).toBeVisible({
    timeout: 10_000,
  });
}

/**
 * Open a document by title from the sidebar.
 */
export async function openDocument(page: Page, title: string): Promise<void> {
  await page.locator("aside").getByText(title).click();
  await expect(page.locator(".cm-content")).toBeVisible({ timeout: 15_000 });
}

/**
 * Collect console errors during a callback.
 */
export async function collectErrors(
  page: Page,
  fn: () => Promise<void>,
): Promise<string[]> {
  const errors: string[] = [];
  const handler = (msg: { type: () => string; text: () => string }) => {
    if (msg.type() === "error") {
      errors.push(msg.text());
    }
  };
  page.on("console", handler);
  await fn();
  page.off("console", handler);
  return errors;
}

/**
 * Create a new folder with the given name. Assumes dashboard is visible.
 */
export async function createFolder(page: Page, name: string): Promise<void> {
  await page.waitForTimeout(2000);
  await page.locator('[title="New Folder"]').click();
  await page.waitForTimeout(1000);
  await page.locator('input[placeholder="Folder name"]').fill(name);
  await page.getByText("Create", { exact: true }).click();

  await expect(page.locator("aside").getByText(name)).toBeVisible({
    timeout: 10_000,
  });
}

/**
 * Right-click on a document/folder in the sidebar to open context menu.
 * Returns a locator for the context menu container (.z-50 overlay).
 */
export async function openContextMenu(page: Page, title: string): Promise<ReturnType<Page["locator"]>> {
  await page.locator("aside").getByText(title).click({ button: "right" });
  const menu = page.locator(".fixed.inset-0 > .absolute");
  await menu.waitFor({ state: "visible", timeout: 5_000 });
  return menu;
}

/**
 * Open the settings dialog from the sidebar user menu.
 */
export async function openSettings(page: Page): Promise<void> {
  await page.locator('button[aria-label="Settings"]').click();
  await page.waitForTimeout(1000);
}

/**
 * Navigate to a tab within the settings dialog.
 */
export async function selectSettingsTab(page: Page, tabName: string): Promise<void> {
  await page.getByRole("tab", { name: tabName }).click();
  await page.waitForTimeout(500);
}

/**
 * Logout from the dashboard. Ends on the login page.
 */
export async function logout(page: Page): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Account");
  await page.getByRole("button", { name: "Log out" }).click();
  await page.waitForTimeout(1000);

  // Confirm logout in dialog
  const confirmBtn = page.locator('[role="dialog"]').getByRole("button", { name: "Log out" });
  if (await confirmBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await confirmBtn.click();
  }

  await expect(page).toHaveURL(/auth\/login|\/$/,  { timeout: 10_000 });
}
