import { test, expect, type Page } from "@playwright/test";
import {
  registerAccount,
  login,
  logout,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { collectErrors } from "../../support/diagnostics";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;
let email: string;

test.describe.serial("Cross-Session Persistence", () => {
  test.beforeAll(async ({ browser }) => {
    const context = await newE2EContext(browser, { bypassCSP: true });
    await context.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    sharedPage = await context.newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  // XSESS-01
  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    email = await registerAccount(sharedPage);
    await createDocument(sharedPage, "Persist Doc");
    await openDocument(sharedPage, "Persist Doc");

    const editor = sharedPage.locator(".cm-content");
    await editor.click();
    await sharedPage.keyboard.insertText("Cross-session content");
    await expectEditorTextContains(sharedPage, "Cross-session content", 10_000);
    await waitForCurrentDocumentSaveIdle(sharedPage);
  });

  test("persists documents and editing across logout and re-login", async () => {
    test.setTimeout(E2E_TIMEOUTS.extendedScenario);

    await test.step("logout", async () => {
      await logout(sharedPage);
    });

    await test.step("login with same credentials reaches dashboard", async () => {
      await login(sharedPage, email);
      await expect(sharedPage.getByRole("button", { name: "New Document" })).toBeVisible({
        timeout: 30_000,
      });
    });

    await test.step("document appears in sidebar after re-login", async () => {
      await expect(
        sharedPage.locator("aside").getByRole("button", { name: "Persist Doc" }),
      ).toBeVisible({ timeout: 60_000 });
    });

    await test.step("document content matches pre-logout content", async () => {
      await openDocument(sharedPage, "Persist Doc");

      await expectEditorTextContains(sharedPage, "Cross-session content", 10_000);
    });

    await test.step("editing after re-login works without errors", async () => {
      const errors = await collectErrors(sharedPage, async () => {
        await openDocument(sharedPage, "Persist Doc");
        await focusEditableEditorEnd(sharedPage);
        await sharedPage.keyboard.press("Enter");
        await sharedPage.keyboard.insertText("Post-login edit");
        await expectEditorTextContains(sharedPage, "Post-login edit", 10_000);
        await waitForCurrentDocumentSaveIdle(sharedPage);
      });

      const syncErrors = errors.filter(
        (e) => e.includes("verification_failed") || e.includes("snapshot recovery failed"),
      );
      expect(syncErrors).toHaveLength(0);
    });
  });
});

async function focusEditableEditorEnd(page: Page): Promise<void> {
  await page.bringToFront();

  const editor = page
    .locator(
      '.cm-content[contenteditable="true"]:visible, .ProseMirror[contenteditable="true"]:visible, [role="textbox"][contenteditable="true"]:visible',
    )
    .first();
  await expect(editor).toBeVisible({ timeout: 30_000 });

  await editor.click({ position: { x: 12, y: 12 }, force: true });
  await editor.evaluate((element) => {
    if (!(element instanceof HTMLElement)) return;
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    range.collapse(false);
    selection?.removeAllRanges();
    selection?.addRange(range);
    element.focus({ preventScroll: true });
  });
  await page.keyboard.press("Control+End");
}

async function waitForCurrentDocumentSaveIdle(page: Page): Promise<void> {
  const documentId = page.url().match(/\/document\/([^/?#]+)/)?.[1];
  if (!documentId) return;

  await page.evaluate(
    (id) => window.__refmdFlushDocumentSync?.(id) ?? false,
    documentId,
  );

  await expect
    .poll(
      () => page.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, documentId),
      {
        timeout: 60_000,
        message: "document did not become save-idle",
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
    });
}
