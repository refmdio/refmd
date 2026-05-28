import { test, expect, type BrowserContext, type Page } from "@playwright/test";
import {
  registerAccount,
  login,
  logout,
  TEST_PASSWORD,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { waitForWorkspaceReady } from "../../support/workspace";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedContext: BrowserContext;
let sharedPage: Page;
let email: string;

test.describe.serial("Login, Logout & Session", () => {
  test.beforeAll(async ({ browser }) => {
    sharedContext = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
    sharedPage = await sharedContext.newPage();
  });

  test.afterAll(async () => {
    await sharedContext.close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    email = await registerAccount(sharedPage);
  });

  test("login, logout, and session persistence work across reloads and tabs", async ({
    browser,
  }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("logout dialog has keep-credentials checkbox", async () => {
      await sharedPage.locator('button[aria-label="Settings"]').click();
      await sharedPage.waitForTimeout(E2E_DELAYS.uiSettle);
      await sharedPage.getByRole("tab", { name: "Account" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);
      await sharedPage.getByRole("button", { name: "Log out" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.uiSettle);

      await expect(sharedPage.locator("#keep-credentials")).toBeVisible({ timeout: 5_000 });
    });

    await test.step("confirm logout redirects to login page", async () => {
      await sharedPage
        .locator('[role="dialog"]')
        .getByRole("button", { name: "Log out" })
        .click();

      await expect(sharedPage).toHaveURL(/auth\/login|\/$/,  { timeout: 10_000 });
    });

    await test.step("keep-me-signed-in checkbox is present on login page", async () => {
      await expect(sharedPage.locator("#remember")).toBeVisible({ timeout: 5_000 });
    });

    await test.step("login with valid credentials", async () => {
      if (!sharedPage.isClosed()) {
        await sharedPage.close();
      }
      sharedPage = await sharedContext.newPage();
      await login(sharedPage, email);
      await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 10_000 });
    });

    await test.step("session persists after page reload", async () => {
      await sharedPage.waitForTimeout(E2E_DELAYS.syncSettle);

      await sharedPage.reload({ waitUntil: "domcontentloaded" });
      await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 120_000 });
      await waitForWorkspaceReady(sharedPage);
    });

    await test.step("session persists after closing a tab without keep-me-signed-in", async () => {
      if (!sharedPage.isClosed()) {
        await sharedPage.close();
      }
      sharedPage = await sharedContext.newPage();
      await login(sharedPage, email, { rememberMe: false });
      await waitForWorkspaceReady(sharedPage);
      await sharedPage.close();

      sharedPage = await sharedContext.newPage();
      await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });

      await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 120_000 });
      await expect(sharedPage.getByText("Password Required")).not.toBeVisible({ timeout: 5_000 });
      await expect(sharedPage.getByText("Recovery Key", { exact: true })).not.toBeVisible({
        timeout: 5_000,
      });
      await waitForWorkspaceReady(sharedPage);
    });

    await test.step("session persists after logout-login-reload cycle", async () => {
      if (!sharedPage.isClosed()) {
        await sharedPage.close();
      }
      sharedPage = await sharedContext.newPage();
      await login(sharedPage, email);
      await waitForWorkspaceReady(sharedPage);
      await logout(sharedPage);
      if (!sharedPage.isClosed()) {
        await sharedPage.close();
      }
      sharedPage = await sharedContext.newPage();
      await login(sharedPage, email);

      await sharedPage.reload({ waitUntil: "domcontentloaded" });
      await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 10_000 });
      await waitForWorkspaceReady(sharedPage);
    });

    await test.step("login rejects invalid credentials", async () => {
      const context = await newE2EContext(browser, { bypassCSP: true });
      const page = await context.newPage();
      try {
        await page.goto("/auth/login", { waitUntil: "domcontentloaded" });

        await page.locator("#email").fill("nonexistent@test.com");
        await page.locator("#password").fill("WrongPassword123!");
        await page.locator('button[type="submit"]').click();

        await expect(page.getByText("Invalid email or password")).toBeVisible({
          timeout: 120_000,
        });
      } finally {
        await context.close();
      }
    });
  });
});
