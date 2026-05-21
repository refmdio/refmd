import { test, expect, type BrowserContext, type Page } from "@playwright/test";
import { registerAccount, login, logout, TEST_PASSWORD, waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

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

  test("setup: register account", async () => {
    test.setTimeout(180_000);
    email = await registerAccount(sharedPage);
  });

  // LOGOUT-01 + LOGOUT-03
  test("logout dialog has keep-credentials checkbox", async () => {
    test.setTimeout(30_000);

    await sharedPage.locator('button[aria-label="Settings"]').click();
    await sharedPage.waitForTimeout(1000);
    await sharedPage.getByRole("tab", { name: "Account" }).click();
    await sharedPage.waitForTimeout(500);
    await sharedPage.getByRole("button", { name: "Log out" }).click();
    await sharedPage.waitForTimeout(1000);

    await expect(sharedPage.locator("#keep-credentials")).toBeVisible({ timeout: 5_000 });
  });

  // LOGOUT-02
  test("confirm logout redirects to login page", async () => {
    test.setTimeout(30_000);

    await sharedPage
      .locator('[role="dialog"]')
      .getByRole("button", { name: "Log out" })
      .click();

    await expect(sharedPage).toHaveURL(/auth\/login|\/$/,  { timeout: 10_000 });
  });

  // LOGIN-03
  test("keep-me-signed-in checkbox is present on login page", async () => {
    test.setTimeout(10_000);
    await expect(sharedPage.locator("#remember")).toBeVisible({ timeout: 5_000 });
  });

  // LOGIN-01
  test("login with valid credentials", async () => {
    test.setTimeout(180_000);
    if (!sharedPage.isClosed()) {
      await sharedPage.close();
    }
    sharedPage = await sharedContext.newPage();
    await login(sharedPage, email);
    await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 10_000 });
  });

  // SESSION-01
  test("session persists after page reload", async () => {
    test.setTimeout(180_000);

    // Wait for session to fully establish after login
    await sharedPage.waitForTimeout(5000);

    await sharedPage.reload({ waitUntil: "domcontentloaded" });
    await expect(sharedPage).toHaveURL(/dashboard/, { timeout: 120_000 });
    await waitForWorkspaceReady(sharedPage);
  });

  test("session persists after closing a tab without keep-me-signed-in", async () => {
    test.setTimeout(180_000);
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

  // SESSION-02
  test("session persists after logout-login-reload cycle", async () => {
    test.setTimeout(180_000);
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

  // LOGIN-02 (last — Argon2 for dummy salt is slow, don't block other tests)
  test("login rejects invalid credentials", async () => {
    test.setTimeout(180_000);
    if (!sharedPage.isClosed()) {
      await sharedPage.close();
    }
    sharedPage = await sharedContext.newPage();
    await sharedPage.goto("/auth/login", { waitUntil: "domcontentloaded" });
    await logout(sharedPage);

    await sharedPage.locator("#email").fill("nonexistent@test.com");
    await sharedPage.locator("#password").fill("WrongPassword123!");
    await sharedPage.locator('button[type="submit"]').click();

    await expect(sharedPage.getByText("Invalid email or password")).toBeVisible({
      timeout: 120_000,
    });
  });
});
