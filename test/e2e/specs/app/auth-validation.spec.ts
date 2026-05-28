import { test, expect } from "@playwright/test";
import {
  TEST_PASSWORD,
  testEmail,
} from "../../support/auth";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test.describe("Auth Form Validation", () => {
  // VAL-01
  test("registration rejects mismatched passwords", async ({ page }) => {
    test.setTimeout(E2E_TIMEOUTS.quick);

    await page.goto("/auth/register");
    await expect(page.locator("#name")).toBeVisible({ timeout: 10_000 });
    await page.locator("#name").fill("E2E User");
    await page.locator("#email").fill(testEmail());
    await page.locator("#password").fill(TEST_PASSWORD);
    await page.locator("#confirm-password").fill("WrongPassword123!");
    await page.locator('button[type="submit"]').click();

    await expect(page.getByText("Passwords do not match")).toBeVisible({
      timeout: 5_000,
    });
  });

  // VAL-02
  test("registration rejects short passwords", async ({ page }) => {
    test.setTimeout(E2E_TIMEOUTS.quick);

    await page.goto("/auth/register");
    await expect(page.locator("#name")).toBeVisible({ timeout: 10_000 });
    await page.locator("#name").fill("E2E User");
    await page.locator("#email").fill(testEmail());
    await page.locator("#password").fill("short");
    await page.locator("#confirm-password").fill("short");
    await page.locator('button[type="submit"]').click();

    await expect(
      page.getByText("Password must be at least 8 characters"),
    ).toBeVisible({ timeout: 5_000 });
  });

  // VAL-03
  test("register page links to login", async ({ page }) => {
    test.setTimeout(E2E_TIMEOUTS.smoke);

    await page.goto("/auth/register");
    await expect(page.locator("#name")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Sign in")).toBeVisible();
  });
});
