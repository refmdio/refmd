import { test, expect, type Page, type Browser, type BrowserContext } from "@playwright/test";
import {
  expectEditorTextContains,
  openDocument,
  openSettings,
  registerAccount,
  selectSettingsTab,
  waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

const DOC_TITLE = "Collab Doc";

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

        const bodyText = ((await page.locator("body").innerText().catch(() => "")) ?? "").trim();
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
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const hasDisconnectedPanels = await page
      .getByText("disconnected", { exact: true })
      .first()
      .isVisible({ timeout: 1_000 })
      .catch(() => false);
    if (hasDisconnectedPanels) {
      await openDashboard(page);
      await waitForWorkspaceReady(page);
    }

    const hasEditor = await page
      .locator('.cm-content, .ProseMirror, [role="textbox"], [contenteditable="true"], textarea')
      .first()
      .isVisible({ timeout: 2_000 })
      .catch(() => false);
    if (!hasEditor) {
      if (/\/document\//.test(page.url())) {
        if (attempt > 0) {
          await page.reload({ waitUntil: "domcontentloaded" });
        }
        await page.waitForTimeout(2_000);
      } else {
        await openDocument(page, title);
        await page.waitForTimeout(2_000);
      }
    }

    const hasEditorAfterRecovery = await page
      .locator('.cm-content, .ProseMirror, [role="textbox"], [contenteditable="true"], textarea')
      .first()
      .isVisible({ timeout: 2_000 })
      .catch(() => false);
    if (!hasEditorAfterRecovery) continue;

    const stillDisconnected = await page
      .getByText("disconnected", { exact: true })
      .first()
      .isVisible({ timeout: 1_000 })
      .catch(() => false);
    if (!stillDisconnected) return;
  }

  throw new Error(`editor was not ready for ${title}`);
}

async function expectTextWithRecovery(page: Page, title: string, text: string): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await expectEditorTextContains(page, text, 60_000);
      return;
    } catch (error) {
      const bodyText = await page.locator("body").innerText().catch(() => "");
      if (attempt > 0 || !bodyText.includes("disconnected")) throw error;
      await openDashboard(page);
      await waitForWorkspaceReady(page);
      await openDocument(page, title);
    }
  }
}

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  const codeMirror = page.locator(".cm-content").first();
  if (await codeMirror.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await codeMirror.click();
    await page.keyboard.press("Control+End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(text);
    return;
  }

  const proseMirror = page.locator(".ProseMirror").first();
  if (await proseMirror.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await proseMirror.click();
    await page.keyboard.press("Control+End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(text);
    return;
  }

  const textbox = page.locator('[role="textbox"], [contenteditable="true"], textarea').last();
  await expect(textbox).toBeVisible({ timeout: 15_000 });
  await textbox.click();
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
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
    .locator(".mosaic-window-toolbar [data-slot='dropdown-menu-trigger'], .mosaic-window-toolbar button")
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
  await expect(activePage.locator("aside").getByText(title)).toBeVisible({ timeout: 15_000 });
  return activePage;
}

async function currentDocumentId(page: Page): Promise<string> {
  await expect
    .poll(() => {
      const match = page.url().match(/\/document\/([^/?#]+)/);
      return match?.[1] ?? "";
    }, {
      timeout: 15_000,
      message: "document route was not established",
    })
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
          const body = ((await activePage.locator("body").textContent().catch(() => "")) ?? "").trim();
          const hasEditor = (await activePage.locator(".cm-content, .ProseMirror").count()) > 0;
          return hasEditor || body.includes(DOC_TITLE) || body.includes("Failed to load document");
        },
        { timeout: 30_000, message: "document route never rendered" },
      )
      .toBe(true)
      .then(() => true)
      .catch(() => false);
    if (rendered) return activePage;
    await activePage.reload({ waitUntil: "domcontentloaded" });
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
  const acceptButton = page.getByRole("button", { name: "Accept Invitation" });
  await expect(acceptButton).toBeVisible({ timeout: 30_000 });
  await acceptButton.click();

  // After acceptance: wait for success or dashboard redirect.
  // The app shows "You've joined the workspace!" then auto-redirects to /dashboard after 2s.
  await expect
    .poll(
      async () => {
        if (/\/dashboard/.test(page.url())) return true;
        const text = await page.locator("body").innerText().catch(() => "");
        return text.includes("joined the workspace");
      },
      { timeout: 60_000, message: "invitation acceptance did not succeed" },
    )
    .toBe(true);

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
  let pageA = await ctxA.newPage();
  await registerAccount(pageA, "Alice");
  pageA = await createDocumentForCollab(pageA, DOC_TITLE);
  await openDocument(pageA, DOC_TITLE);
  const docId = await currentDocumentId(pageA);
  await typeInVisibleEditor(pageA, "Hello from Alice.");
  await expectEditorTextContains(pageA, "Hello from Alice.", 30_000);
  await pageA.waitForTimeout(3_000);

  const ctxB = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  let pageB = await ctxB.newPage();
  const emailB = await registerAccount(pageB, "Bob");

  const inviteLink = await inviteUser(pageA, emailB);
  expect(inviteLink).toContain("/invite#token=");
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
    test.setTimeout(180_000);

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
    test.setTimeout(180_000);

    const { ctxA, pageA, ctxB, pageB } = await setupSharedDocument(browser);
    try {
      await ensureEditorReady(pageA, DOC_TITLE);
      await ensureEditorReady(pageB, DOC_TITLE);
      await typeInVisibleEditor(pageB, "Bob");
      await expectEditorTextContains(pageB, "Bob", 15_000);
      await pageB.waitForTimeout(3_000);
      await ensureEditorReady(pageA, DOC_TITLE);
      await expectTextWithRecovery(pageA, DOC_TITLE, "Bob");
    } finally {
      await closeContexts([ctxB, ctxA]);
    }
  });

  test("split editors exchange awareness without recursive cursor failures", async ({ browser }) => {
    test.setTimeout(180_000);

    const { ctxA, pageA, ctxB, pageB } = await setupSharedDocument(browser);
    const capture = collectConsoleErrorsAcross([pageA, pageB]);
    try {
      await ensureEditorReady(pageA, DOC_TITLE);
      await ensureEditorReady(pageB, DOC_TITLE);
      await switchToSplitMode(pageA);
      await switchToSplitMode(pageB);

      await pageA.locator(".cm-content").click();
      await pageA.keyboard.insertText("Alice split awareness. ");
      await pageB.locator(".ProseMirror").click();
      await pageB.keyboard.insertText("Bob split awareness. ");
      await pageA.locator(".ProseMirror").click();
      await pageB.locator(".cm-content").click();
      await pageA.waitForTimeout(18_000);

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
