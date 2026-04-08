import { test, expect, type Page } from "@playwright/test";
import { TEST_PASSWORD, testEmail } from "./helpers";

async function reachRecoveryKey(page: Page, email = testEmail()) {
  await page.goto("/auth/register");
  await page.locator("#name").fill("E2E User");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 120_000,
  });

  return email;
}

test.describe("Account Registration", () => {
  // REG-01
  test("Argon2 derivation completes and recovery key screen appears", async ({ page }) => {
    test.setTimeout(180_000);

    await reachRecoveryKey(page);
  });

  // REG-02
  test("recovery key displays 24 words", async ({ page }) => {
    test.setTimeout(180_000);

    await reachRecoveryKey(page);
    await expect(page.getByText("24 words")).toBeVisible({ timeout: 5_000 });
  });

  // REG-03
  test("show/hide toggle reveals and hides recovery words", async ({ page }) => {
    test.setTimeout(180_000);

    await reachRecoveryKey(page);

    // Words should be hidden by default (masked as "------")
    await expect(page.getByText("------").first()).toBeVisible({ timeout: 5_000 });

    // Click Show to reveal words
    await page.getByRole("button", { name: "Show" }).click();
    await page.waitForTimeout(500);

    // Masked text should be gone, replaced by actual words
    await expect(page.getByText("------").first()).not.toBeVisible({ timeout: 5_000 });

    // Click Hide to re-mask
    await page.getByRole("button", { name: "Hide" }).click();
    await page.waitForTimeout(500);

    // Masked text should be back
    await expect(page.getByText("------").first()).toBeVisible({ timeout: 5_000 });
  });

  // REG-05
  test("download button downloads recovery key file", async ({ page }) => {
    test.setTimeout(180_000);

    await reachRecoveryKey(page);

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Download" }).click(),
    ]);

    expect(download.suggestedFilename()).toContain("recovery");
  });

  // REG-06 + REG-07
  test("continue is disabled until key is backed up, then reaches dashboard", async ({ page }) => {
    test.setTimeout(180_000);

    await reachRecoveryKey(page);

    // Continue should be disabled before backup
    const continueBtn = page.getByRole("button", { name: "Continue" });
    await expect(continueBtn).toBeDisabled({ timeout: 5_000 });

    // Download to enable continue
    await page.getByRole("button", { name: "Download" }).click();
    await page.waitForTimeout(1000);
    await page.evaluate(() => window.scrollTo(0, 9999));
    await page.waitForTimeout(1000);

    // Now continue should be enabled
    await continueBtn.click({ timeout: 10_000 });
    await expect(page).toHaveURL(/dashboard/, { timeout: 10_000 });
  });
});
