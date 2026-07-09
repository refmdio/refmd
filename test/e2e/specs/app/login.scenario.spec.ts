import {
  test,
  expect,
  chromium,
  firefox,
  type BrowserContext,
  type BrowserType,
  type Page,
} from "@playwright/test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  registerAccount,
  login,
  logout,
  TEST_PASSWORD,
} from "../../support/auth";
import { launchPersistentE2EContext, newE2EContext } from "../../support/context";
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

async function launchRestartContext(
  browserType: BrowserType,
  userDataDir: string,
): Promise<BrowserContext> {
  return launchPersistentE2EContext(browserType, userDataDir, {
    acceptDownloads: true,
    headless: true,
    ...(browserType === chromium ? { args: ["--disable-web-security"] } : {}),
  });
}

async function firstPage(context: BrowserContext): Promise<Page> {
  return context.pages()[0] ?? context.newPage();
}

test("keep-me-signed-in controls encrypted key restoration across browser restart", async ({
  browserName,
}) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const browserType: BrowserType = browserName === "firefox" ? firefox : chromium;
  const enabledUserDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "refmd-kmsi-on-e2e-"));
  const disabledUserDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "refmd-kmsi-off-e2e-"));
  let context: BrowserContext | null = null;

  try {
    context = await launchRestartContext(browserType, enabledUserDataDir);
    let page = await firstPage(context);
    const enabledEmail = await registerAccount(page);
    await logout(page);
    await login(page, enabledEmail, { rememberMe: true });
    await waitForWorkspaceReady(page);

    await context.close();
    context = await launchRestartContext(browserType, enabledUserDataDir);
    page = await firstPage(context);
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });

    await expect(page).toHaveURL(/dashboard/, { timeout: 120_000 });
    await expect(page.getByText("Password Required")).not.toBeVisible({ timeout: 5_000 });
    await waitForWorkspaceReady(page);

    await context.close();
    context = await launchRestartContext(browserType, disabledUserDataDir);
    page = await firstPage(context);
    const disabledEmail = await registerAccount(page);
    await logout(page);
    await login(page, disabledEmail, { rememberMe: false });
    await waitForWorkspaceReady(page);

    await context.close();
    context = await launchRestartContext(browserType, disabledUserDataDir);
    page = await firstPage(context);
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });

    await expect(page).toHaveURL(/dashboard/, { timeout: 120_000 });
    await expect(page.getByText("Password Required")).toBeVisible({ timeout: 120_000 });
    await expect(page.getByRole("button", { name: "Unlock" })).toBeVisible({ timeout: 5_000 });
  } finally {
    if (context) {
      await context.close().catch(() => undefined);
    }
    fs.rmSync(enabledUserDataDir, { recursive: true, force: true });
    fs.rmSync(disabledUserDataDir, { recursive: true, force: true });
  }
});
