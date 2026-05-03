import { expect, test, type WebSocketRoute } from "@playwright/test";
import {
  TEST_PASSWORD,
  createDocument,
  expectEditorTextContains,
  openDocument,
  readEditorText,
  registerAccount,
  waitForWorkspaceReady,
  newE2EContext,
} from "./helpers";

async function loginForDeviceRegistration(page: import("@playwright/test").Page, email: string) {
  await page.goto("/auth/login");
  await expect(page.locator("#email")).toBeVisible({ timeout: 30_000 });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/devices\/register/, { timeout: 120_000 });
}

async function typeInEditor(page: import("@playwright/test").Page, text: string): Promise<void> {
  const editor = page
    .locator('.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"]')
    .first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click({ force: true });
  await editor.evaluate((element) => {
    if (element instanceof HTMLElement) element.focus();
  });
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
}

test("same-account device resumes document sync after websocket reconnect", async ({ browser }) => {
  test.setTimeout(360_000);

  const contextA = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  const contextB = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  const socketsB: WebSocketRoute[] = [];
  const consoleMessages: string[] = [];
  const stateHistory: unknown[] = [];
  let allowSocketB = true;

  await contextB.routeWebSocket((url) => url.pathname.startsWith("/api/socket"), (socket) => {
    socketsB.push(socket);
    if (!allowSocketB) {
      void socket.close({ code: 1001 });
      return;
    }
    socket.connectToServer();
  });
  await Promise.all([
    contextA.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    }),
    contextB.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    }),
  ]);

  const pageA = await contextA.newPage();
  const pageB = await contextB.newPage();
  for (const page of [pageA, pageB]) {
    page.on("console", (msg) => {
      const text = msg.text();
      if (msg.type() === "error" || text.includes("[ws]") || text.includes("[auto-sync]")) {
        consoleMessages.push(text);
      }
    });
  }
  try {
    const email = await registerAccount(pageA);
    await createDocument(pageA, "Reconnect Sync Doc");
    await openDocument(pageA, "Reconnect Sync Doc");
    const documentId = pageA.url().match(/\/document\/([^/?#]+)/)?.[1];
    if (!documentId) throw new Error(`Reconnect Sync Doc id not found in URL: ${pageA.url()}`);
    await typeInEditor(pageA, "baseline-from-device-a");

    await loginForDeviceRegistration(pageB, email);
    if (
      !(await pageA
        .getByRole("button", { name: /Emojis Match.*Approve/i })
        .isVisible({ timeout: 10_000 })
        .catch(() => false))
    ) {
      await pageA.goto("/dashboard", { waitUntil: "domcontentloaded" });
      await waitForWorkspaceReady(pageA);
    }
    await expect(pageA.getByRole("button", { name: /Emojis Match.*Approve/i })).toBeVisible({
      timeout: 120_000,
    });
    await pageA.getByRole("button", { name: /Emojis Match.*Approve/i }).click();
    await expect(pageB).toHaveURL(/dashboard/, { timeout: 120_000 });
    await waitForWorkspaceReady(pageB);
    await openDocument(pageA, "Reconnect Sync Doc");
    await openDocument(pageB, "Reconnect Sync Doc");
    await expectEditorTextContains(pageB, "baseline-from-device-a", 60_000);

    allowSocketB = false;
    await Promise.all(socketsB.map((socket) => socket.close({ code: 1001 })));
    await expect(pageB.getByText("Offline")).toBeVisible({ timeout: 30_000 });

    allowSocketB = true;
    await expect(pageB.getByText("Offline")).toBeHidden({ timeout: 90_000 });
    await expect
      .poll(
        async () => {
          const state = await pageB.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            documentId,
          );
          stateHistory.push(state);
          return state;
        },
        {
          timeout: 90_000,
          message: `device B sync state did not recover:\nstate=${JSON.stringify(stateHistory)}\nconsole=${consoleMessages.join("\n")}`,
        },
      )
      .toMatchObject({
        autoSync: true,
        channelState: "joined",
        error: null,
        initialized: true,
        readOnly: false,
        reconnecting: false,
        sending: false,
        syncPaused: false,
      });

    await typeInEditor(pageB, "after-reconnect-from-device-b");
    await expect
      .poll(() => readEditorText(pageB), {
        timeout: 10_000,
        message: `device B edit was not locally applied: ${consoleMessages.join("\n")}`,
      })
      .toContain("after-reconnect-from-device-b");
    await expectEditorTextContains(pageA, "after-reconnect-from-device-b", 90_000);

    await typeInEditor(pageA, "after-reconnect-from-device-a");
    await expectEditorTextContains(pageB, "after-reconnect-from-device-a", 90_000);
  } finally {
    await contextA.close();
    await contextB.close();
  }
});
