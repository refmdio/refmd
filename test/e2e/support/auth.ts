import { expect, type Page } from "@playwright/test";
import { e2eBaseURL } from "./context";
import { openSettings, selectSettingsTab } from "./settings";
import { E2E_DELAYS } from "./timeouts";
import {
  waitForWorkspaceReady,
  waitForWorkspaceReadyOrLogin,
  waitForWorkspaceReadyWithDiagnostics,
} from "./workspace";

export const TEST_PASSWORD = "TestPassword123!";

export function testEmail(): string {
  return `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@test.com`;
}

async function openRegisterForm(page: Page): Promise<void> {
  await page.goto("/auth/register");
  const nameInput = page.locator("#name");
  if (await nameInput.isVisible({ timeout: 5_000 }).catch(() => false)) {
    return;
  }
  const registerLink = page.getByRole("link", { name: "Register" });
  if (await registerLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
    await registerLink.click();
  }
  await expect(nameInput).toBeVisible({ timeout: 60_000 });
}

export async function registerAccount(page: Page, name = "E2E User"): Promise<string> {
  return (await registerAccountWithRecoveryPhrase(page, name)).email;
}

export async function registerAccountWithRecoveryPhrase(
  page: Page,
  name = "E2E User",
): Promise<{ email: string; mnemonic: string }> {
  const email = testEmail();

  await page.addInitScript(() => {
    window.__refmdE2EClientLogs = [];
    window.addEventListener("refmd:client-log", (event) => {
      window.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
    });
  });

  await openRegisterForm(page);
  const nameInput = page.locator("#name");
  await expect(nameInput).toBeVisible({ timeout: 60_000 });
  await nameInput.fill(name);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  const recoveryKeyHeading = page.getByText("Recovery Key", { exact: true });
  const registrationError = page.getByRole("alert");
  await Promise.race([
    expect(recoveryKeyHeading).toBeVisible({ timeout: 180_000 }),
    registrationError.waitFor({ state: "visible", timeout: 180_000 }).then(async () => {
      if (await recoveryKeyHeading.isVisible().catch(() => false)) return;
      throw new Error(
        `registration failed: ${(await registrationError.textContent())?.trim() ?? "unknown error"}`,
      );
    }),
  ])
    .catch(async (error) => {
      const snapshot = await page
        .evaluate(() => ({
          url: window.location.href,
          bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200),
        }))
        .catch((snapshotError) => ({ diagnosticError: String(snapshotError) }));
      throw new Error(
        `registration did not reach Recovery Key screen: ${JSON.stringify(snapshot)}\n${String(
          error,
        )}`,
      );
    });

  await page.getByRole("button", { name: "Show" }).click();
  const words = await page.locator("div.grid.grid-cols-3 > div > span:nth-child(2)").allTextContents();
  expect(words).toHaveLength(24);
  const mnemonic = words.join(" ");

  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(E2E_DELAYS.uiSettle);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(E2E_DELAYS.uiSettle);
  const continueButton = page.getByRole("button", { name: "Continue" });
  await expect(continueButton).toBeEnabled({ timeout: 60_000 });
  await continueButton.click({ timeout: 60_000 });

  await expect(page).toHaveURL(/dashboard/, { timeout: 60_000 });
  try {
    await Promise.race([
      waitForWorkspaceReady(page),
      page
        .waitForFunction(
          () =>
            window.__refmdE2EClientLogs?.some(
              (entry) =>
                typeof entry === "object" &&
                entry !== null &&
                "message" in entry &&
                entry.message === "workspace_verification_failed",
            ) === true,
          undefined,
          { timeout: 120_000 },
        )
        .then(async () => {
          const logs = await page.evaluate(() => window.__refmdE2EClientLogs ?? []);
          throw new Error(`workspace verification failed: ${JSON.stringify(logs)}`);
        }),
    ]);
  } catch (error) {
    const diagnostics = await page.evaluate(() => ({
      clientLogs: window.__refmdE2EClientLogs ?? [],
      url: window.location.href,
    }));
    throw new Error(
      `registration workspace initialization failed: ${JSON.stringify(diagnostics)}\n${String(error)}`,
    );
  }
  return { email, mnemonic };
}

export async function login(
  page: Page,
  email: string,
  options?: {
    allowDeviceRegistration?: boolean;
    rememberMe?: boolean;
    _retriedAfterLoginRedirect?: boolean;
    _diagnostics?: string[];
  },
): Promise<void> {
  const diagnostics = options?._diagnostics ?? [];
  const ownsDiagnostics = !options?._diagnostics;
  const record = (message: string) => {
    if (diagnostics.length < 80) diagnostics.push(`${Date.now()} ${message}`);
  };
  const responseHandler = (response: { url(): string; status(): number }) => {
    const url = new URL(response.url(), e2eBaseURL);
    if (
      url.pathname.startsWith("/api/auth/") ||
      url.pathname.startsWith("/api/devices/") ||
      url.pathname.startsWith("/api/workspaces") ||
      url.pathname === "/api/settings" ||
      url.pathname === "/api/security/notifications"
    ) {
      record(`${response.status()} ${url.pathname}`);
    }
  };
  const navigationHandler = (frame: { parentFrame(): unknown; url(): string }) => {
    if (frame.parentFrame()) return;
    record(`NAV ${new URL(frame.url(), e2eBaseURL).pathname}`);
  };
  if (ownsDiagnostics) {
    page.on("response", responseHandler);
    page.on("framenavigated", navigationHandler);
  }

  try {
    const isWorkspaceVisible = async () =>
      page
        .getByRole("button", { name: "New Document" })
        .isVisible({ timeout: 2_000 })
        .catch(() => false);

    await page.goto("/auth/login", { waitUntil: "domcontentloaded" }).catch(async (error) => {
      const message = String(error);
      if (!message.includes("ERR_ABORTED") && !message.includes("NS_BINDING_ABORTED")) throw error;
      await page.waitForLoadState("domcontentloaded").catch(() => undefined);
      await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
    });
    await page.waitForTimeout(E2E_DELAYS.uiSettle);
    if (
      /\/dashboard/.test(page.url()) ||
      (options?.allowDeviceRegistration && /\/devices\/register/.test(page.url())) ||
      (await isWorkspaceVisible())
    ) {
      if (/\/dashboard/.test(page.url())) {
        if (await waitForWorkspaceReadyOrLogin(page)) return;
        if (!options?._retriedAfterLoginRedirect) {
          await login(page, email, {
            ...options,
            _retriedAfterLoginRedirect: true,
            _diagnostics: diagnostics,
          });
          return;
        }
        await waitForWorkspaceReadyWithDiagnostics(page, diagnostics);
      }
      return;
    }
    const emailInput = page.locator("#email");
    if (!(await emailInput.isVisible({ timeout: 5_000 }).catch(() => false))) {
      const signInButton = page.getByRole("button", { name: "Sign In" });
      if (await signInButton.isVisible({ timeout: 5_000 }).catch(() => false)) {
        await signInButton.click();
      }
    }
    await expect
      .poll(
        async () => {
          if (
            /\/dashboard/.test(page.url()) ||
            (options?.allowDeviceRegistration && /\/devices\/register/.test(page.url())) ||
            (await isWorkspaceVisible())
          ) {
            return true;
          }
          return emailInput.isVisible({ timeout: 1_000 }).catch(() => false);
        },
        {
          timeout: 30_000,
          message: "login page never settled to dashboard, device registration, or email form",
        },
      )
      .toBe(true);
    if (
      /\/dashboard/.test(page.url()) ||
      (options?.allowDeviceRegistration && /\/devices\/register/.test(page.url())) ||
      (await isWorkspaceVisible())
    ) {
      if (/\/dashboard/.test(page.url())) {
        if (await waitForWorkspaceReadyOrLogin(page)) return;
        if (!options?._retriedAfterLoginRedirect) {
          await login(page, email, {
            ...options,
            _retriedAfterLoginRedirect: true,
            _diagnostics: diagnostics,
          });
          return;
        }
        await waitForWorkspaceReadyWithDiagnostics(page, diagnostics);
      }
      return;
    }
    await expect(emailInput).toBeVisible({ timeout: 30_000 });
    await emailInput.fill(email);
    await page.locator("#password").fill(TEST_PASSWORD);
    if (options?.rememberMe === true) {
      await page.getByText("Keep me signed in", { exact: true }).click({ timeout: 5_000 });
    }
    await page.locator('button[type="submit"]').click();

    await expect(page).toHaveURL(
      options?.allowDeviceRegistration ? /dashboard|devices\/register/ : /dashboard/,
      { timeout: 120_000 },
    );
    if (/\/dashboard/.test(page.url())) {
      if (await waitForWorkspaceReadyOrLogin(page)) return;
      if (!options?._retriedAfterLoginRedirect) {
        await login(page, email, {
          ...options,
          _retriedAfterLoginRedirect: true,
          _diagnostics: diagnostics,
        });
        return;
      }
      await waitForWorkspaceReadyWithDiagnostics(page, diagnostics);
    }
  } finally {
    if (ownsDiagnostics) {
      page.off("response", responseHandler);
      page.off("framenavigated", navigationHandler);
    }
  }
}

export async function logout(page: Page): Promise<void> {
  const loginForm = page.locator("#email");
  if (await loginForm.isVisible({ timeout: 5_000 }).catch(() => false)) {
    return;
  }

  const settingsButton = page.locator('button[aria-label="Settings"]');
  if (!(await settingsButton.isVisible({ timeout: 5_000 }).catch(() => false))) {
    await page.goto("/auth/login", { waitUntil: "domcontentloaded" });
    if (await loginForm.isVisible({ timeout: 10_000 }).catch(() => false)) {
      return;
    }
    await expect(settingsButton).toBeVisible({ timeout: 20_000 });
  }

  await openSettings(page);
  await selectSettingsTab(page, "Account");
  await page.getByRole("button", { name: "Log out" }).click();
  await page.waitForTimeout(E2E_DELAYS.uiSettle);

  const confirmBtn = page.locator('[role="dialog"]').getByRole("button", { name: "Log out" });
  if (await confirmBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await confirmBtn.click();
  }

  await expect(page).toHaveURL(/auth\/login|\/$/, { timeout: 10_000 });
  await expect(loginForm).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("button", { name: "New Document" })).toBeHidden({
    timeout: 30_000,
  });
}
