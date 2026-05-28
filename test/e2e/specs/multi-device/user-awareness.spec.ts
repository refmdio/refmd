import { test, expect, type Page, type Browser, type BrowserContext } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import {
  openSettings,
  selectSettingsTab,
} from "../../support/settings";
import { waitForWorkspaceReady } from "../../support/workspace";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

const DOC_TITLE = "Collab Doc";

async function installClientDiagnostics(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    type ClientLogDetail = {
      level?: string;
      message?: string;
      context?: unknown;
      at?: string;
    };
    const normalize = (value: unknown): unknown => {
      if (value instanceof Error) {
        return {
          name: value.name,
          message: value.message,
          stack: value.stack,
          code: (value as Error & { code?: string }).code,
        };
      }
      if (Array.isArray(value)) return value.map(normalize);
      if (value && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
            key,
            normalize(nested),
          ]),
        );
      }
      return value;
    };
    const w = window as Window & { __refmdE2EClientLogs?: ClientLogDetail[] };
    window.__REFMD_E2E__ = true;
    w.__refmdE2EClientLogs = [];
    window.addEventListener("refmd:client-log", (event) => {
      const detail = (event as CustomEvent<ClientLogDetail>).detail;
      w.__refmdE2EClientLogs?.push(normalize(detail) as ClientLogDetail);
    });
  });
}

async function clientDiagnostics(page: Page): Promise<unknown> {
  return page
    .evaluate(() => {
      const w = window as Window & { __refmdE2EClientLogs?: unknown[] };
      return (w.__refmdE2EClientLogs ?? []).slice(-10);
    })
    .catch(() => []);
}

async function documentText(page: Page, documentId: string): Promise<string | null> {
  return page
    .evaluate(
      (id) =>
        (
          window as Window & {
            __refmdGetDocumentText?: (documentId: string) => string | null;
          }
        ).__refmdGetDocumentText?.(id) ?? null,
      documentId,
    )
    .catch(() => null);
}

async function documentSyncState(page: Page, documentId: string): Promise<unknown> {
  return page
    .evaluate(
      (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
      documentId,
    )
    .catch(() => null);
}

async function openDashboard(page: Page): Promise<void> {
  await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
  await expect
    .poll(
      async () => {
        const newDocumentVisible = await page
          .locator('[title="New Document"]')
          .isVisible({ timeout: 1_000 })
          .catch(() => false);
        if (newDocumentVisible) return true;

        const bodyText = (
          (await page
            .locator("body")
            .innerText()
            .catch(() => "")) ?? ""
        ).trim();
        return bodyText.length > 0;
      },
      {
        timeout: 20_000,
        message: "dashboard never rendered",
      },
    )
    .toBe(true);
}

async function ensureEditorReady(page: Page, title: string): Promise<void> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const bodyText = await page
      .locator("body")
      .innerText()
      .catch(() => "");
    const needsRecovery =
      bodyText.includes("disconnected") ||
      bodyText.includes("Failed to load document") ||
      bodyText.includes("initial_load_failed");
    if (needsRecovery || (attempt > 0 && /\/document\//.test(page.url()))) {
      await openDashboard(page);
      await waitForWorkspaceReady(page);
      await openDocument(page, title);
      await page.waitForTimeout(E2E_DELAYS.uiSettle);
    } else if (!/\/document\//.test(page.url())) {
      await openDocument(page, title);
      await page.waitForTimeout(E2E_DELAYS.uiSettle);
    }

    const editorReady = await page
      .locator('.cm-content, .ProseMirror, [role="textbox"], [contenteditable="true"], textarea')
      .first()
      .isVisible({ timeout: 5_000 })
      .catch(() => false);
    if (!editorReady) continue;

    const stillDisconnected = await page
      .getByText("disconnected", { exact: true })
      .first()
      .isVisible({ timeout: 1_000 })
      .catch(() => false);
    if (!stillDisconnected) {
      const documentId = await currentDocumentId(page).catch(() => null);
      if (documentId) {
        await waitForDocumentSyncReady(page, documentId);
      }
      return;
    }
  }

  const bodyText = await page
    .locator("body")
    .innerText()
    .catch(() => "");
  throw new Error(
    `editor was not ready for ${title}: ${JSON.stringify({
      url: page.url(),
      bodyText: bodyText.slice(0, 500),
      clientLogs: await clientDiagnostics(page),
    })}`,
  );
}

async function waitForDocumentSyncReady(page: Page, documentId: string): Promise<void> {
  const states: unknown[] = [];
  try {
    await expect
      .poll(
        async () => {
          const state = await page.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            documentId,
          );
          states.push(state);
          return state;
        },
        {
          timeout: 60_000,
          message: "document sync did not become ready",
        },
      )
      .toMatchObject({
        channelState: "joined",
        error: null,
        initialized: true,
        pendingSnapshot: false,
        pendingUpdate: false,
        reconnecting: false,
        syncPaused: false,
      });
  } catch (error) {
    throw new Error(
      `${error instanceof Error ? error.message : String(error)} ${JSON.stringify({
        recentStates: states.slice(-5),
      })}`,
    );
  }
}

async function expectTextWithRecovery(page: Page, title: string, text: string): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await expectEditorTextContains(page, text, 60_000);
      return;
    } catch (error) {
      const bodyText = await page
        .locator("body")
        .innerText()
        .catch(() => "");
      const needsRecovery =
        bodyText.includes("disconnected") ||
        bodyText.includes("Failed to load document") ||
        bodyText.includes("initial_load_failed");
      if (attempt > 0 || !needsRecovery) {
        const diagnostics = await clientDiagnostics(page);
        const documentId = await currentDocumentId(page).catch(() => null);
        throw new Error(
          `${error instanceof Error ? error.message : String(error)} ${JSON.stringify({
            clientLogs: diagnostics,
            documentId,
            documentText: documentId ? await documentText(page, documentId) : null,
            syncState: documentId ? await documentSyncState(page, documentId) : null,
            url: page.url(),
          })}`,
        );
      }
      await openDashboard(page);
      await waitForWorkspaceReady(page);
      await openDocument(page, title);
    }
  }
}

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  const candidates = [
    page.locator('.cm-content[contenteditable="true"]:visible').first(),
    page.locator('.ProseMirror[contenteditable="true"]:visible').first(),
    page.locator('[role="textbox"]:visible, [contenteditable="true"]:visible, textarea:visible').last(),
  ];

  for (const editor of candidates) {
    if (!(await editor.isVisible({ timeout: 2_000 }).catch(() => false))) continue;
    for (const input of [
      () => page.keyboard.insertText(text),
      () => editor.pressSequentially(text, { delay: 10 }),
    ]) {
      await editor.click({ force: true });
      await editor.evaluate((el) => (el as HTMLElement).focus());
      await page.keyboard.press("End");
      await page.keyboard.press("Enter");
      await input();
      if (
        await expectEditorTextContains(page, text, 5_000)
          .then(() => true)
          .catch(() => false)
      ) {
        return;
      }
    }
  }

  throw new Error(`failed to type into visible editor: ${text}`);
}

async function appendDocumentText(
  page: Page,
  text: string,
  options: { preferUiInput?: boolean } = {},
): Promise<void> {
  await page.bringToFront();
  const documentId = await currentDocumentId(page);
  await waitForDocumentSyncReady(page, documentId);
  const appended = options.preferUiInput
    ? false
    : await page
        .evaluate(
          ({ id, value }) => {
            const append = (
              window as Window & {
                __refmdAppendDocumentText?: (documentId: string, text: string) => boolean;
              }
            ).__refmdAppendDocumentText;
            return append?.(id, `\n${value}`) ?? false;
          },
          { id: documentId, value: text },
        )
        .catch(() => false);

  if (!appended) {
    await typeInVisibleEditor(page, text);
  }

  await expectEditorTextContains(page, text, 15_000);
  await flushDocumentSync(page, documentId);
  await waitForDocumentSyncReady(page, documentId);
}

async function flushDocumentSync(page: Page, documentId: string): Promise<void> {
  await page.bringToFront();
  await page
    .evaluate(
      async (id) =>
        await (
          window as Window & {
            __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
          }
        ).__refmdFlushDocumentSync?.(id),
      documentId,
    )
    .catch(() => false);
}

async function switchToSplitMode(page: Page): Promise<void> {
  const cmVisible = await page
    .locator(".cm-content")
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  const pmVisible = await page
    .locator(".ProseMirror")
    .isVisible({ timeout: 2_000 })
    .catch(() => false);
  if (cmVisible && pmVisible) return;

  const trigger = page
    .locator(
      ".mosaic-window-toolbar [data-slot='dropdown-menu-trigger'], .mosaic-window-toolbar button",
    )
    .last();
  await expect(trigger).toBeVisible({ timeout: 10_000 });
  await trigger.click();
  const menuContent = page.locator('[data-slot="dropdown-menu-content"]');
  await expect(menuContent).toBeVisible({ timeout: 5_000 });
  await menuContent
    .locator('[data-slot="dropdown-menu-item"]', { hasText: "Switch to Split" })
    .click();
  await expect(page.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
}

function collectConsoleErrorsAcross(pages: Page[]): {
  errors: string[];
  stop: () => void;
} {
  const errors: string[] = [];
  const handlers = pages.map((page) => {
    const handler = (msg: { type: () => string; text: () => string }) => {
      if (msg.type() === "error") {
        errors.push(msg.text());
      }
    };
    page.on("console", handler);
    return { page, handler };
  });
  return {
    errors,
    stop: () => {
      for (const { page, handler } of handlers) {
        page.off("console", handler);
      }
    },
  };
}

async function createDocumentForCollab(page: Page, title: string): Promise<Page> {
  const activePage = page.isClosed() ? await page.context().newPage() : page;
  if (!/\/dashboard/.test(activePage.url())) {
    await openDashboard(activePage);
  }
  await waitForWorkspaceReady(activePage);
  const newDocumentButton = activePage.locator('[title="New Document"]');
  await expect(newDocumentButton).toBeVisible({ timeout: 30_000 });
  await expect(newDocumentButton).toBeEnabled({ timeout: 30_000 });
  await newDocumentButton.click({ force: true });
  const titleInput = activePage.locator('input[placeholder="Document title"]');
  await expect(titleInput).toBeVisible({ timeout: 10_000 });
  await titleInput.fill(title);
  await activePage.getByText("Create", { exact: true }).click();
  await expect(activePage.locator("aside").getByText(title)).toBeVisible({ timeout: 90_000 });
  return activePage;
}

async function currentDocumentId(page: Page): Promise<string> {
  await expect
    .poll(
      () => {
        const match = page.url().match(/\/document\/([^/?#]+)/);
        return match?.[1] ?? "";
      },
      {
        timeout: 15_000,
        message: "document route was not established",
      },
    )
    .not.toBe("");
  const match = page.url().match(/\/document\/([^/?#]+)/);
  return match![1];
}

async function openDocumentRoute(page: Page, documentId: string): Promise<Page> {
  let activePage = page;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    if (activePage.isClosed()) {
      activePage = await page.context().newPage();
    }
    await activePage.goto(`/document/${documentId}`, { waitUntil: "domcontentloaded" });
    const rendered = await expect
      .poll(
        async () => {
          const body = (
            (await activePage
              .locator("body")
              .textContent()
              .catch(() => "")) ?? ""
          ).trim();
          const hasEditor = (await activePage.locator(".cm-content, .ProseMirror").count()) > 0;
          return hasEditor || body.includes("Failed to load document");
        },
        { timeout: 30_000, message: "document route never rendered" },
      )
      .toBe(true)
      .then(() => true)
      .catch(() => false);
    if (rendered) return activePage;
    try {
      await openDashboard(activePage);
      await waitForWorkspaceReady(activePage);
      await openDocument(activePage, DOC_TITLE);
      return activePage;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (attempt === 2 || !message.includes("key_directory_fetch_failed")) {
        throw error;
      }
      await activePage.reload({ waitUntil: "domcontentloaded" });
    }
  }
  throw new Error(`document route remained blank for ${documentId}`);
}

async function inviteUser(page: Page, email: string): Promise<string> {
  await openSettings(page);
  await selectSettingsTab(page, "Workspace");
  await page.getByRole("button", { name: "Invite" }).click();
  await page.locator("#invite-email").fill(email);
  await page.getByRole("button", { name: "Create Invitation" }).click();
  await expect(page.getByText("Invitation created")).toBeVisible({ timeout: 30_000 });
  const link = await page.locator('[role="dialog"] input[readonly]').inputValue();
  await page.getByRole("button", { name: "Done" }).click();
  await page.keyboard.press("Escape");
  return link;
}

async function acceptInvitation(page: Page, link: string): Promise<Page> {
  await page.goto(link, { waitUntil: "domcontentloaded" });

  // Wait for the Accept button - crypto worker must be ready for it to appear
  const acceptButton = page.getByRole("button", { name: /accept invitation/i });
  await acceptButton.waitFor({ state: "visible", timeout: 30_000 });
  await acceptButton.click();

  // After acceptance: wait for success or dashboard redirect.
  // The app shows "You've joined the workspace!" then auto-redirects to /dashboard after 2s.
  await expect
    .poll(
      async () => {
        if (/\/dashboard/.test(page.url())) return "accepted";
        const text = await page
          .locator("body")
          .innerText()
          .catch(() => "");
        return text.includes("joined the workspace")
          ? "accepted"
          : JSON.stringify({ url: page.url(), bodyText: text.slice(0, 240) });
      },
      { timeout: 60_000, message: "invitation acceptance did not succeed" },
    )
    .toBe("accepted");

  // Click "Go to Workspace" if still visible, otherwise wait for auto-redirect
  const goToWorkspace = page.getByRole("button", { name: "Go to Workspace" });
  if (await goToWorkspace.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await goToWorkspace.click();
  }

  await expect.poll(() => /\/dashboard/.test(page.url()), { timeout: 30_000 }).toBe(true);
  await waitForWorkspaceReady(page);
  return page;
}

async function setupSharedDocument(browser: Browser): Promise<{
  ctxA: BrowserContext;
  pageA: Page;
  ctxB: BrowserContext;
  pageB: Page;
  docId: string;
}> {
  const ctxA = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  await installClientDiagnostics(ctxA);
  let pageA = await ctxA.newPage();
  await registerAccount(pageA, "Alice");
  pageA = await createDocumentForCollab(pageA, DOC_TITLE);
  await openDocument(pageA, DOC_TITLE);
  const docId = await currentDocumentId(pageA);
  await typeInVisibleEditor(pageA, "Hello from Alice.");
  await expectEditorTextContains(pageA, "Hello from Alice.", 30_000);

  const ctxB = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  await installClientDiagnostics(ctxB);
  let pageB = await ctxB.newPage();
  const emailB = await registerAccount(pageB, "Bob");

  const inviteLink = await inviteUser(pageA, emailB);
  expect(inviteLink).toMatch(/\/invite#it=.+&ib=.+/);
  pageB = await acceptInvitation(pageB, inviteLink);
  pageB = await openDocumentRoute(pageB, docId);

  return { ctxA, pageA, ctxB, pageB, docId };
}

async function closeContexts(contexts: Array<BrowserContext | undefined>): Promise<void> {
  for (const context of contexts) {
    await context?.close();
  }
}

test.describe("Multi-User Awareness & Presence (4-23)", () => {
  test("invited user can accept the invitation and open the shared document", async ({
    browser,
  }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    const { ctxA, pageA, ctxB, pageB } = await setupSharedDocument(browser);
    try {
      await ensureEditorReady(pageB, DOC_TITLE);
      await expect(pageB).toHaveURL(/\/document\//, { timeout: 30_000 });
      await expectEditorTextContains(pageB, "Hello from Alice.", 60_000);
    } finally {
      await closeContexts([ctxB, ctxA]);
    }
  });

  test("invited user edits and owner receives the update", async ({ browser }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    const { ctxA, pageA, ctxB, pageB } = await setupSharedDocument(browser);
    try {
      await ensureEditorReady(pageA, DOC_TITLE);
      await ensureEditorReady(pageB, DOC_TITLE);
      await appendDocumentText(pageB, "Bob");
      await ensureEditorReady(pageA, DOC_TITLE);
      await expectTextWithRecovery(pageA, DOC_TITLE, "Bob");
    } finally {
      await closeContexts([ctxB, ctxA]);
    }
  });

  test("split editors exchange awareness without recursive cursor failures", async ({
    browser,
  }) => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    const { ctxA, pageA, ctxB, pageB } = await setupSharedDocument(browser);
    const capture = collectConsoleErrorsAcross([pageA, pageB]);
    try {
      await ensureEditorReady(pageA, DOC_TITLE);
      await ensureEditorReady(pageB, DOC_TITLE);
      await switchToSplitMode(pageA);
      await switchToSplitMode(pageB);

      await pageA.locator(".cm-content").click();
      await appendDocumentText(pageA, "Alice split awareness.");
      await expectTextWithRecovery(pageB, DOC_TITLE, "Alice split awareness.");
      await pageB.locator(".ProseMirror").click();
      await appendDocumentText(pageB, "Bob split awareness.");
      await expectEditorTextContains(pageB, "Bob split awareness.", 15_000);
      await pageA.locator(".ProseMirror").click();
      await pageB.locator(".cm-content").click();

      const recursiveFailures = capture.errors.filter(
        (error) =>
          error.includes("too much recursion") ||
          error.includes("Ephemeral processing error") ||
          error.includes("CodeMirror plugin crashed") ||
          error.includes("cursor-map-error"),
      );
      expect(recursiveFailures).toHaveLength(0);
    } finally {
      capture.stop();
      await closeContexts([ctxB, ctxA]);
    }
  });
});
