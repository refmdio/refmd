import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import {
  createDocument,
  expectEditorTextContains,
  openContextMenu,
  openDocument,
  registerAccount,
  newE2EContext,
} from "./helpers";

const DOC_TITLE = "Anonymous Edit Share Sync";
const LOGGED_IN_DOC_TITLE = "Logged In Share Edit Sync";
const SHARE_DOCUMENT_ROUTE_RE =
  /\/share\/d\/[^/#]+(?:#(?:cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}(?:&s=[A-Za-z0-9_-]{22})?|s=[A-Za-z0-9_-]{22}))?$/;

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

  await dialog.getByRole("button", { name: "Create Link" }).click();

  const input = dialog.locator("input[readonly]");
  await expect(input).toHaveValue(/\/share\/[^/#]+#cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}$/, {
    timeout: 60_000,
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

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  const codeMirror = page
    .locator('.cm-content[contenteditable="true"]')
    .first();
  if (await codeMirror.isVisible({ timeout: 30_000 }).catch(() => false)) {
    await codeMirror.click({ force: true });
    await codeMirror.evaluate((element) => {
      if (element instanceof HTMLElement) element.focus();
    });
    await page.keyboard.press("Control+End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(text);
    return;
  }

  const proseMirror = page
    .locator('.ProseMirror[contenteditable="true"]')
    .first();
  if (await proseMirror.isVisible({ timeout: 30_000 }).catch(() => false)) {
    await proseMirror.click({ force: true });
    await proseMirror.evaluate((element) => {
      if (element instanceof HTMLElement) element.focus();
    });
    await page.keyboard.press("Control+End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(text);
    return;
  }

  const textbox = page
    .locator('[role="textbox"], [contenteditable="true"], textarea')
    .last();
  await expect(textbox).toBeVisible({ timeout: 15_000 });
  await textbox.click({ force: true });
  await textbox.evaluate((element) => {
    if (element instanceof HTMLElement) element.focus();
  });
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
}

async function typeLineBurst(
  page: Page,
  prefix: string,
  count: number,
): Promise<void> {
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
    await page.waitForTimeout(45);
  }
}

test("anonymous edit share keeps syncing across burst edits and reload", async ({
  browser,
}, testInfo) => {
  test.setTimeout(300_000);

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
    const ownerPage = await ownerContext.newPage();
    const guestPage = await guestContext.newPage();
    diagnostics = collectSyncDiagnostics([ownerPage, guestPage]);

    await registerAccount(ownerPage);
    await createDocument(ownerPage, DOC_TITLE);
    await openDocument(ownerPage, DOC_TITLE);

    const shareLink = await createEditShareLinkFromUi(ownerPage, DOC_TITLE);

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForEditor(guestPage);

    await typeInVisibleEditor(ownerPage, "owner-before-burst");
    await expectEditorTextContains(guestPage, "owner-before-burst", 60_000);

    await typeLineBurst(guestPage, "guest-edit", 120);
    await expectEditorTextContains(ownerPage, "guest-edit-119", 90_000);

    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_DOCUMENT_ROUTE_RE, {
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

test("logged-in browser can edit through a share link without breaking sync", async ({
  browser,
}, testInfo) => {
  test.setTimeout(300_000);

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
    await expect(recipientPage).toHaveURL(SHARE_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForEditor(recipientPage);

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
