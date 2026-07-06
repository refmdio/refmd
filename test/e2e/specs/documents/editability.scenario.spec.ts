import { test, expect, type Page } from "@playwright/test";
import { registerAccount, TEST_PASSWORD, testEmail } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { collectErrors } from "../../support/diagnostics";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";
import { waitForWorkspaceReady } from "../../support/workspace";

async function currentDocumentId(page: Page): Promise<string> {
  await expect
    .poll(() => page.url().match(/\/document\/([^/?#]+)/)?.[1] ?? "", {
      timeout: 30_000,
      message: "new document route was not established",
    })
    .not.toBe("");
  return page.url().match(/\/document\/([^/?#]+)/)![1];
}

async function syncState(page: Page, documentId: string): Promise<unknown> {
  return page.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, documentId);
}

async function waitForEditableDocument(page: Page, documentId: string): Promise<void> {
  await expect
    .poll(() => syncState(page, documentId), {
      timeout: 90_000,
      message: "document did not remain editable",
    })
    .toMatchObject({
      channelState: "joined",
      error: null,
      initialized: true,
      readOnly: false,
      reconnecting: false,
      syncPaused: false,
    });

  await expect(page.locator('.cm-content[contenteditable="true"]').first()).toBeVisible({
    timeout: 30_000,
  });
}

async function waitForSaveIdle(page: Page, documentId: string): Promise<void> {
  await page.evaluate(
    (id) =>
      (
        window as Window & {
          __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
        }
      ).__refmdFlushDocumentSync?.(id) ?? false,
    documentId,
  );

  await expect
    .poll(() => syncState(page, documentId), {
      timeout: 90_000,
      message: "new document did not finish saving",
    })
    .toMatchObject({
      error: null,
      initialized: true,
      pendingSave: false,
      pendingSnapshot: false,
      pendingUpdate: false,
      readOnly: false,
      reconnecting: false,
      sending: false,
      syncPaused: false,
      unsavedCanonicalText: false,
    });
}

async function documentBodyText(page: Page): Promise<string> {
  return page.evaluate(() => document.body.textContent ?? "");
}

async function documentDiagnostics(page: Page, documentId: string): Promise<unknown> {
  return page.evaluate((id) => {
    const w = window as Window & {
      __refmdGetDocumentSyncState?: (documentId: string) => unknown;
      __refmdE2ESyncPerf?: unknown[];
    };
    return {
      bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200) ?? "",
      syncPerf: (w.__refmdE2ESyncPerf ?? []).slice(-40),
      syncState: w.__refmdGetDocumentSyncState?.(id) ?? null,
      url: window.location.href,
    };
  }, documentId);
}

async function createDocumentWithEnter(page: Page, title: string): Promise<void> {
  await page.locator('[title="New Document"]').click();
  const titleInput = page.locator('input[placeholder="Document title"]');
  await expect(titleInput).toBeVisible({ timeout: 30_000 });
  await titleInput.fill(title);
  await titleInput.press("Enter");
  await expect(page.locator("aside").getByText(title, { exact: true })).toBeVisible({
    timeout: 90_000,
  });
}

async function openDocumentFromSidebar(page: Page, title: string): Promise<void> {
  const row = page.locator("aside").getByText(title, { exact: true }).first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  await expect(page.locator(".cm-content").first()).toBeVisible({ timeout: 90_000 });
}

async function registerAccountWithStaleWorkspaceSelection(page: Page): Promise<void> {
  const email = testEmail();
  await page.goto("/auth/register");
  await expect(page.locator("#name")).toBeVisible({ timeout: 60_000 });
  await page.locator("#name").fill("E2E User");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator("#confirm-password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();

  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible({
    timeout: 180_000,
  });
  await page.evaluate(() => {
    localStorage.setItem("refmd_workspace_id", crypto.randomUUID());
  });
  await page.getByRole("button", { name: "Download" }).click();
  await page.waitForTimeout(E2E_DELAYS.uiSettle);
  await page.evaluate(() => window.scrollTo(0, 9999));
  await page.waitForTimeout(E2E_DELAYS.uiSettle);
  const continueButton = page.getByRole("button", { name: "Continue" });
  await expect(continueButton).toBeEnabled({ timeout: 60_000 });
  await continueButton.click({ timeout: 60_000 });

  await expect(page).toHaveURL(/dashboard/, { timeout: 60_000 });
  await waitForWorkspaceReady(page);
}

function relevantDocumentFailures(errors: string[]): string[] {
  return errors.filter(
    (error) =>
      error.includes("reconnect_failed") ||
      error.includes("initial_load_failed") ||
      error.includes("verification_failed") ||
      error.includes("canonical_") ||
      error.includes("sync_gap") ||
      error.includes("read-only") ||
      error.includes("readOnly"),
  );
}

function observeDocumentSessionFailures(page: Page) {
  let countPostAuth = false;
  const observations = {
    authMe401BeforePostAuth: 0,
    authMe401AfterPostAuth: 0,
    postAuthConsoleErrors: [] as string[],
    postAuthAuthMe401Urls: [] as string[],
  };

  const responseHandler = (response: { url(): string; status(): number }) => {
    const url = response.url();
    let pathname = "";
    try {
      pathname = new URL(url).pathname;
    } catch {
      return;
    }
    if (pathname !== "/api/auth/me" || response.status() !== 401) return;
    if (!countPostAuth) {
      observations.authMe401BeforePostAuth += 1;
      return;
    }
    observations.authMe401AfterPostAuth += 1;
    observations.postAuthAuthMe401Urls.push(url);
  };

  const consoleHandler = (message: { type(): string; text(): string }) => {
    if (!countPostAuth || message.type() !== "error") return;
    const text = message.text();
    if (
      text.includes("/api/auth/me") ||
      text.includes("reconnect_failed") ||
      text.includes("initial_load_failed") ||
      text.includes("read-only") ||
      text.includes("readOnly")
    ) {
      observations.postAuthConsoleErrors.push(text);
    }
  };

  page.on("response", responseHandler);
  page.on("console", consoleHandler);

  return {
    markPostAuth: () => {
      countPostAuth = true;
    },
    observations,
    dispose: () => {
      page.off("response", responseHandler);
      page.off("console", consoleHandler);
    },
  };
}

test("newly created document stays editable after heading input and reload", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const context = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();

  try {
    const errors = await collectErrors(page, async () => {
      await registerAccount(page);
      const title = `Editability Regression ${Date.now()}`;
      await createDocumentWithEnter(page, title);
      await openDocumentFromSidebar(page, title);

      const documentId = await currentDocumentId(page);
      await waitForEditableDocument(page, documentId);

      const editor = page.locator('.cm-content[contenteditable="true"]').first();
      await editor.click({ position: { x: 24, y: 14 } });
      await page.keyboard.insertText("# aue");

      await expectEditorTextContains(page, "# aue", 30_000);
      await page.waitForTimeout(E2E_DELAYS.awarenessSettle);
      await waitForEditableDocument(page, documentId);
      await expect(documentBodyText(page), {
        message: `document failed after heading input: ${JSON.stringify(
          await documentDiagnostics(page, documentId),
        )}`,
      }).resolves.not.toContain("reconnect_failed");

      await page.reload({ waitUntil: "domcontentloaded" });
      await expect
        .poll(() => page.url(), {
          timeout: 30_000,
          message: "new document route was not preserved across reload",
        })
        .toContain(`/document/${documentId}`);

      await waitForEditableDocument(page, documentId);
      await expect(documentBodyText(page), {
        message: `document failed after reload: ${JSON.stringify(
          await documentDiagnostics(page, documentId),
        )}`,
      }).resolves.not.toContain("initial_load_failed");
      await expectEditorTextContains(page, "# aue", 90_000);
      await waitForSaveIdle(page, documentId);
    });

    expect(relevantDocumentFailures(errors)).toEqual([]);
  } finally {
    await context.close();
  }
});

test("new registration recovers from stale persisted workspace before first edit", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const context = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const failureObserver = observeDocumentSessionFailures(page);

  try {
    await registerAccountWithStaleWorkspaceSelection(page);
    failureObserver.markPostAuth();

    const title = `Stale Workspace Regression ${Date.now()}`;
    await createDocumentWithEnter(page, title);
    await openDocumentFromSidebar(page, title);

    const documentId = await currentDocumentId(page);
    const editor = page.locator(".cm-content").first();
    await expect(editor).toBeVisible({ timeout: 90_000 });
    await editor.click({ position: { x: 24, y: 14 } });
    await page.keyboard.insertText("# aue");

    await expectEditorTextContains(page, "# aue", 15_000);
    await waitForEditableDocument(page, documentId);
    await waitForSaveIdle(page, documentId);

    expect(failureObserver.observations.authMe401AfterPostAuth, {
      message: `post-auth /api/auth/me 401 observed: ${JSON.stringify(
        failureObserver.observations,
      )}`,
    }).toBe(0);
    expect(relevantDocumentFailures(failureObserver.observations.postAuthConsoleErrors), {
      message: `post-auth document console failures observed: ${JSON.stringify(
        failureObserver.observations,
      )}`,
    }).toEqual([]);
  } finally {
    failureObserver.dispose();
    await context.close();
  }
});

test("newly created document accepts immediate first edit without post-auth session failure", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const context = await newE2EContext(browser, { bypassCSP: true });
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const failureObserver = observeDocumentSessionFailures(page);

  try {
    await registerAccount(page);
    failureObserver.markPostAuth();

    const title = `Immediate Edit Regression ${Date.now()}`;
    await createDocumentWithEnter(page, title);
    await openDocumentFromSidebar(page, title);

    const documentId = await currentDocumentId(page);
    const editor = page.locator(".cm-content").first();
    await expect(editor).toBeVisible({ timeout: 90_000 });
    await editor.click({ position: { x: 24, y: 14 } });
    await page.keyboard.insertText("# aue");

    await expectEditorTextContains(page, "# aue", 15_000);
    await waitForEditableDocument(page, documentId);
    await waitForSaveIdle(page, documentId);

    await page.reload({ waitUntil: "domcontentloaded" });
    await expect
      .poll(() => page.url(), {
        timeout: 30_000,
        message: "new document route was not preserved across reload",
      })
      .toContain(`/document/${documentId}`);

    await waitForEditableDocument(page, documentId);
    await expectEditorTextContains(page, "# aue", 90_000);
    await waitForSaveIdle(page, documentId);

    expect(failureObserver.observations.authMe401AfterPostAuth, {
      message: `post-auth /api/auth/me 401 observed: ${JSON.stringify(
        failureObserver.observations,
      )}`,
    }).toBe(0);
    expect(relevantDocumentFailures(failureObserver.observations.postAuthConsoleErrors), {
      message: `post-auth document console failures observed: ${JSON.stringify(
        failureObserver.observations,
      )}`,
    }).toEqual([]);
  } finally {
    failureObserver.dispose();
    await context.close();
  }
});
