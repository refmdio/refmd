import {
  expect,
  test,
  type BrowserContext,
  type Page,
  type WebSocketRoute,
} from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openContextMenu,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

const DOC_TITLE = "Anonymous Edit Share Sync";
const LOGGED_IN_DOC_TITLE = "Logged In Share Edit Sync";
const SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE =
  /\/share\/(?:d\/)?[^/#]+(?:#(?:cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}(?:&s=[A-Za-z0-9_-]{22})?|s=[A-Za-z0-9_-]{22}))?$/;
const SHARE_LINK_CREATION_TIMEOUT_MS = 120_000;

function currentDocumentId(page: Page): string {
  const path = new URL(page.url()).pathname;
  const match = path.match(/^\/document\/([^/]+)$/) ?? path.match(/^\/share\/d\/([^/]+)$/);
  if (!match) throw new Error(`current path is not a document route: ${page.url()}`);
  return match[1];
}

async function waitForDocumentSyncReady(page: Page): Promise<void> {
  const documentId = currentDocumentId(page);
  const states: unknown[] = [];
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
        message: `document sync did not become ready: ${JSON.stringify(states.slice(-5))}`,
      },
    )
    .toMatchObject({
      channelState: "joined",
      error: null,
      initialized: true,
      pendingSave: false,
      pendingSnapshot: false,
      pendingUpdate: false,
      reconnecting: false,
      sending: false,
      syncPaused: false,
      unsavedCanonicalText: false,
    });
}

async function flushDocumentSync(page: Page): Promise<void> {
  await page.bringToFront();
  const documentId = currentDocumentId(page);
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

function collectSyncDiagnostics(pages: Page[]): {
  messages: string[];
  stop: () => void;
} {
  const messages: string[] = [];
  const handlers = pages.map((page) => {
    const handler = (msg: { type: () => string; text: () => string }) => {
      const text = msg.text();
      if (
        msg.type() === "error" ||
        text.includes("[anti-rollback]") ||
        text.includes("[ws]") ||
        text.includes("DocumentSyncError")
      ) {
        messages.push(text);
      }
    };
    page.on("console", handler);
    return { page, handler };
  });

  return {
    messages,
    stop: () => {
      for (const { page, handler } of handlers) {
        page.off("console", handler);
      }
    },
  };
}

function criticalSyncMessages(messages: string[]): string[] {
  return messages.filter((message) =>
    [
      "Clock gap",
      "State Inconsistency",
      "Snapshot changed but no proof chain",
      "Version regression",
      "rollback attack",
      "verification_failed",
      "key_directory_pin_required",
      "initial_load_failed",
      "reconnect_failed",
      "connection_error",
      "sync gap detected",
    ].some((needle) => message.includes(needle)),
  );
}

async function createEditShareLinkFromUi(
  page: Page,
  title: string,
): Promise<string> {
  await page.bringToFront();
  await waitForDocumentSyncReady(page);
  const menu = await openContextMenu(page, title);
  await menu.getByRole("menuitem", { name: "Share" }).click();

  const dialog = page.locator('[role="dialog"]');
  await expect(dialog.getByText("Share Access")).toBeVisible({
    timeout: 10_000,
  });
  await dialog.getByRole("button", { name: "Create new link" }).click();

  await dialog.locator("#share-permission").click();
  const option = page
    .locator('[data-slot="select-content"] [data-slot="select-item"]')
    .filter({ hasText: "Edit" })
    .last();
  await expect(option).toBeVisible({ timeout: 5_000 });
  await option.click();

  const createLinkButton = dialog.getByRole("button", { name: "Create Link" });
  await expect(createLinkButton).toBeEnabled({ timeout: 30_000 });
  await createLinkButton.click({ timeout: 30_000 });

  const input = dialog.locator("input[readonly]");
  await expect(input)
    .toHaveValue(/\/share\/[^/#]+#cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}$/, {
      timeout: SHARE_LINK_CREATION_TIMEOUT_MS,
    })
    .catch(async (error) => {
      const snapshot = await page
        .evaluate(() => ({
          url: window.location.href,
          dialogs: Array.from(document.querySelectorAll('[role="dialog"]')).map((node) =>
            node.textContent?.replace(/\s+/g, " ").trim(),
          ),
          bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200),
        }))
        .catch((err) => ({ diagnosticError: String(err) }));
      throw new Error(`edit share link was not created: ${JSON.stringify(snapshot)}\n${String(error)}`);
    });
  const link = await input.inputValue();
  await page.keyboard.press("Escape");
  return link;
}

async function waitForEditor(page: Page): Promise<void> {
  await expect
    .poll(
      async () =>
        page.evaluate(
          () =>
            document.querySelectorAll(
              '.cm-content, .ProseMirror, [role="textbox"], [contenteditable="true"], textarea',
            ).length,
        ),
      {
        timeout: 60_000,
        message: "editor did not mount",
      },
    )
    .toBeGreaterThan(0);
}

async function waitForShareEditor(page: Page, fullShareLink: string): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const state = await page
      .waitForFunction(
        () => {
          const editorCount = document.querySelectorAll(
            '.cm-content, .ProseMirror, [role="textbox"], [contenteditable="true"], textarea',
          ).length;
          if (editorCount > 0) return "mounted";
          const bodyText = document.body.textContent ?? "";
          if (bodyText.includes("share_key_ref_unavailable")) return "key-ref-unavailable";
          return false;
        },
        undefined,
        { timeout: 60_000 },
      )
      .then((handle) => handle.jsonValue() as Promise<"mounted" | "key-ref-unavailable">)
      .catch(() => "timeout" as const);

    if (state === "mounted") return;
    if (state === "key-ref-unavailable" && attempt === 0) {
      await page.goto(fullShareLink, { waitUntil: "domcontentloaded" });
      await expect(page).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
        timeout: 60_000,
      });
      continue;
    }

    throw new Error(`share editor did not mount: ${state}`);
  }
}

async function expectWritableEditor(page: Page): Promise<void> {
  await expect(
    page
      .locator(
        '.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"], [role="textbox"][contenteditable="true"], textarea',
      )
      .first(),
  ).toBeVisible({ timeout: 30_000 });
}

async function expectNoDocumentSecurityFailure(page: Page): Promise<void> {
  await expect
    .poll(
      async () => page.locator("body").innerText().catch(() => ""),
      {
        timeout: 5_000,
        message: "document security failure was visible",
      },
    )
    .not.toMatch(/verification_failed|State Inconsistency|Clock rollback/i);
}

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  await page.bringToFront();
  await waitForDocumentSyncReady(page);
  const documentId = currentDocumentId(page);
  const appendedWithHook = await page
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
  if (appendedWithHook) {
    await expectEditorTextContains(page, text, 15_000);
    await flushDocumentSync(page);
    await waitForDocumentSyncReady(page);
    return;
  }

  const candidates = [
    page.locator('.cm-content[contenteditable="true"]').first(),
    page.locator('.ProseMirror[contenteditable="true"]').first(),
    page.locator('[role="textbox"], [contenteditable="true"], textarea').last(),
  ];

  for (const editor of candidates) {
    if (!(await editor.isVisible({ timeout: 10_000 }).catch(() => false))) continue;
    for (const input of [
      () => page.keyboard.insertText(text),
      () => editor.pressSequentially(text, { delay: 10 }),
    ]) {
      await editor.click({ force: true });
      await editor.evaluate((element) => {
        if (element instanceof HTMLElement) element.focus();
      });
      await page.keyboard.press("Control+End");
      await page.keyboard.press("Enter");
      await input();
      if (
        await expectEditorTextContains(page, text, 5_000)
          .then(() => true)
          .catch(() => false)
      ) {
        await flushDocumentSync(page);
        await waitForDocumentSyncReady(page);
        return;
      }
    }
  }

  throw new Error(`failed to type into visible editor: ${text}`);
}

async function typeLineBurst(
  page: Page,
  prefix: string,
  count: number,
): Promise<void> {
  await waitForDocumentSyncReady(page);
  await page.bringToFront();
  const documentId = currentDocumentId(page);
  const appendedWithHook = await page
    .evaluate(
      async ({ id, linePrefix, lineCount }) => {
        const append = (
          window as Window & {
            __refmdAppendDocumentText?: (documentId: string, text: string) => boolean;
          }
        ).__refmdAppendDocumentText;
        if (!append) return false;
        for (let i = 0; i < lineCount; i += 1) {
          if (!append(id, `\n${linePrefix}-${i}`)) return false;
          await new Promise((resolve) => setTimeout(resolve, 45));
        }
        return true;
      },
      { id: documentId, linePrefix: prefix, lineCount: count },
    )
    .catch(() => false);
  if (appendedWithHook) {
    await expectEditorTextContains(page, `${prefix}-${count - 1}`, 30_000);
    await flushDocumentSync(page);
    await waitForDocumentSyncReady(page);
    return;
  }

  const editor = page
    .locator(
      '.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"]',
    )
    .first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click({ force: true });
  await editor.evaluate((element) => {
    if (element instanceof HTMLElement) element.focus();
  });
  await page.keyboard.press("Control+End");

  for (let i = 0; i < count; i += 1) {
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(`${prefix}-${i}`);
    await page.waitForTimeout(E2E_DELAYS.inputPropagation);
  }
  await expectEditorTextContains(page, `${prefix}-${count - 1}`, 30_000);
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

test("anonymous edit share keeps syncing across burst edits and reload", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    guestContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    await ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    await guestContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    const ownerPage = await ownerContext.newPage();
    const guestPage = await guestContext.newPage();
    diagnostics = collectSyncDiagnostics([ownerPage, guestPage]);

    await registerAccount(ownerPage);
    await createDocument(ownerPage, DOC_TITLE);
    await openDocument(ownerPage, DOC_TITLE);

    const shareLink = await createEditShareLinkFromUi(ownerPage, DOC_TITLE);

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForEditor(guestPage);

    await typeInVisibleEditor(ownerPage, "owner-before-burst");
    await expectEditorTextContains(guestPage, "owner-before-burst", 60_000);

    await typeLineBurst(guestPage, "guest-edit", 120);
    await expectEditorTextContains(ownerPage, "guest-edit-119", 90_000);
    await expectNoDocumentSecurityFailure(ownerPage);
    await expectWritableEditor(ownerPage);

    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForEditor(guestPage);
    await expectEditorTextContains(guestPage, "guest-edit-119", 60_000);

    await ownerPage.bringToFront();
    await waitForEditor(ownerPage);
    await typeInVisibleEditor(ownerPage, "owner-after-guest-reload");
    await expectEditorTextContains(
      ownerPage,
      "owner-after-guest-reload",
      10_000,
    );
    await guestPage.bringToFront();
    await expectEditorTextContains(
      guestPage,
      "owner-after-guest-reload",
      60_000,
    );

    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      await testInfo.attach("sync-diagnostics", {
        body: [
          "sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
        ].join("\n"),
        contentType: "text/plain",
      });
    }
    throw err;
  } finally {
    diagnostics?.stop();
    await guestContext?.close();
    await ownerContext?.close();
  }
});

test("anonymous edit share keeps owner writable after manual guest edit", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.offlineShell);

  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;
  const guestSockets: WebSocketRoute[] = [];
  let allowGuestSocket = true;

  try {
    ownerContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    guestContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    await ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      window.addEventListener("refmd:client-log", (event) => {
        console.error(`[client-log] ${JSON.stringify((event as CustomEvent).detail)}`);
      });
    });
    await guestContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      window.addEventListener("refmd:client-log", (event) => {
        console.error(`[client-log] ${JSON.stringify((event as CustomEvent).detail)}`);
      });
    });
    await guestContext.routeWebSocket((url) => url.pathname.startsWith("/api/socket"), (socket) => {
      guestSockets.push(socket);
      if (!allowGuestSocket) {
        void socket.close({ code: 1001 });
        return;
      }
      socket.connectToServer();
    });
    const ownerPage = await ownerContext.newPage();
    const guestPage = await guestContext.newPage();
    diagnostics = collectSyncDiagnostics([ownerPage, guestPage]);
    let blockOwnerVerificationDirectory = false;
    await ownerPage.route("**/api/documents/*/share-verification-directory", async (route) => {
      if (!blockOwnerVerificationDirectory) {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          workspace_devices: [],
          share_participant_devices: [],
        }),
      });
    });

    await registerAccount(ownerPage);
    await createDocument(ownerPage, DOC_TITLE);
    await openDocument(ownerPage, DOC_TITLE);
    const shareLink = await createEditShareLinkFromUi(ownerPage, DOC_TITLE);

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForEditor(guestPage);

    blockOwnerVerificationDirectory = true;
    await typeInVisibleEditor(guestPage, "manual-anonymous-edit");
    await expectEditorTextContains(ownerPage, "manual-anonymous-edit", 90_000);
    await expectNoDocumentSecurityFailure(ownerPage);
    await expectWritableEditor(ownerPage);

    for (let i = 0; i < 8; i += 1) {
      const text = `manual-anonymous-followup-${i}`;
      await typeInVisibleEditor(guestPage, text);
      await expectEditorTextContains(ownerPage, text, 90_000);
      await expectNoDocumentSecurityFailure(ownerPage);
      await expectWritableEditor(ownerPage);
    }

    allowGuestSocket = false;
    await Promise.all(guestSockets.map((socket) => socket.close({ code: 1001 })));
    await expect(guestPage.getByText("Offline")).toBeVisible({ timeout: 30_000 });
    allowGuestSocket = true;
    await expect(guestPage.getByText("Offline")).toBeHidden({ timeout: 90_000 });
    await typeInVisibleEditor(guestPage, "manual-anonymous-after-guest-reconnect");
    await expectEditorTextContains(ownerPage, "manual-anonymous-after-guest-reconnect", 90_000);
    await expectNoDocumentSecurityFailure(ownerPage);
    await expectWritableEditor(ownerPage);

    await typeInVisibleEditor(ownerPage, "owner-after-manual-anonymous-edit");
    await expectEditorTextContains(
      guestPage,
      "owner-after-manual-anonymous-edit",
      60_000,
    );

    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      await testInfo.attach("sync-diagnostics", {
        body: [
          "sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
        ].join("\n"),
        contentType: "text/plain",
      });
    }
    throw err;
  } finally {
    diagnostics?.stop();
    await guestContext?.close();
    await ownerContext?.close();
  }
});

test("logged-in browser can edit through a share link without breaking sync", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  let ownerContext: BrowserContext | undefined;
  let recipientContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    recipientContext = await newE2EContext(browser, {
      bypassCSP: true,
      acceptDownloads: true,
    });
    await ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    await recipientContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    const ownerPage = await ownerContext.newPage();
    const recipientPage = await recipientContext.newPage();
    diagnostics = collectSyncDiagnostics([ownerPage, recipientPage]);

    await registerAccount(ownerPage);
    await createDocument(ownerPage, LOGGED_IN_DOC_TITLE);
    await openDocument(ownerPage, LOGGED_IN_DOC_TITLE);
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      LOGGED_IN_DOC_TITLE,
    );

    await registerAccount(recipientPage, "Logged In Share Recipient");
    await recipientPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(recipientPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(recipientPage, shareLink);

    await typeInVisibleEditor(recipientPage, "logged-in-share-edit");
    await expectEditorTextContains(ownerPage, "logged-in-share-edit", 60_000);

    await typeInVisibleEditor(ownerPage, "owner-after-logged-in-share-edit");
    await expectEditorTextContains(
      recipientPage,
      "owner-after-logged-in-share-edit",
      60_000,
    );

    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      const recipientPageSnapshot = recipientContext?.pages()[0]
        ? await recipientContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      await testInfo.attach("sync-diagnostics", {
        body: [
          "sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `recipient-page: ${JSON.stringify(recipientPageSnapshot)}`,
        ].join("\n"),
        contentType: "text/plain",
      });
    }
    throw err;
  } finally {
    diagnostics?.stop();
    await recipientContext?.close();
    await ownerContext?.close();
  }
});
