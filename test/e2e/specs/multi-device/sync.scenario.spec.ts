/**
 * Single-User Multi-Device Sync Test
 *
 * Same account, two browser contexts (= two devices).
 * Verifies that edits on device A appear on device B and vice versa.
 */

import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import {
  TEST_PASSWORD,
  registerAccount,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains, readEditorText } from "../../support/editor";
import { waitForWorkspaceReady } from "../../support/workspace";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  const codeMirror = page.locator(".cm-content").first();
  if (await codeMirror.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await codeMirror.click();
    await page.keyboard.press("End");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(text);
    return;
  }

  const proseMirror = page.locator(".ProseMirror").first();
  await expect(proseMirror).toBeVisible({ timeout: 15_000 });
  await proseMirror.click();
  await page.keyboard.press("End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
}

async function readMarkdownEditorText(page: Page, documentId: string): Promise<string> {
  const documentText = await page.evaluate((id) => {
    const target = window as Window & {
      __refmdGetDocumentText?: (documentId: string) => string | null;
    };
    return target.__refmdGetDocumentText?.(id) ?? null;
  }, documentId);
  if (documentText !== null) return documentText;

  const lines = await page.locator(".cm-content .cm-line").allTextContents();
  if (lines.length > 0) return lines.join("\n");
  return readEditorText(page);
}

async function appendDocumentTextViaSyncHook(
  page: Page,
  documentId: string,
  text: string,
): Promise<void> {
  await expect
    .poll(
      () =>
        page.evaluate(
          ([id, value]) => window.__refmdAppendDocumentText?.(id, value) === true,
          [documentId, text] as const,
        ),
      {
        timeout: 10_000,
        message: "document append test hook did not accept text",
      },
    )
    .toBe(true);
}

async function typeMarkdownMarkerAtDocumentEnd(page: Page, marker: string): Promise<void> {
  const editor = page.locator(".cm-content").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click();
  await page.keyboard.press(process.platform === "darwin" ? "Meta+End" : "Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(marker);
}

async function expectDocumentTextContains(
  page: Page,
  documentId: string,
  snippet: string,
  timeout = 30_000,
): Promise<void> {
  await expect
    .poll(() => readMarkdownEditorText(page, documentId), {
      timeout,
      message: `document text never contained expected text: ${snippet}`,
    })
    .toContain(snippet);
}

async function expectDocumentTextContainsWithDiagnostics(
  page: Page,
  documentId: string,
  snippet: string,
  timeout: number,
  label: string,
  pages: { name: string; page: Page }[],
): Promise<void> {
  await expectDocumentTextContains(page, documentId, snippet, timeout).catch(async (error) => {
    const state = await collectDivergenceDiagnostics(label, documentId, pages);
    throw new Error(`${error instanceof Error ? error.message : String(error)}; ${state}`);
  });
}

async function expectMarkdownEditorsConverged(
  pageA: Page,
  pageB: Page,
  documentId: string,
  timeout = 30_000,
): Promise<void> {
  await expect
    .poll(
      async () => {
        const [textA, textB] = await Promise.all([
          readMarkdownEditorText(pageA, documentId),
          readMarkdownEditorText(pageB, documentId),
        ]);
        return { converged: textA === textB };
      },
      {
        timeout,
        message: "markdown editor text did not converge exactly across devices",
      },
    )
    .toMatchObject({ converged: true });
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

async function collectClientLogs(page: Page): Promise<unknown[]> {
  return page.evaluate(() => {
    const w = window as Window & { __refmdE2EClientLogs?: unknown[] };
    return (w.__refmdE2EClientLogs ?? []).slice(-20);
  });
}

async function collectSyncPerf(page: Page): Promise<unknown[]> {
  return page.evaluate(() => {
    const w = window as Window & { __refmdE2ESyncPerf?: unknown[] };
    const relevantEvents = new Set([
      "canonical_server_doc_apply",
      "device_key_cache_key_changed",
      "document_sync_fail_closed",
      "local_edit_observed",
      "remote_update_applied",
      "remote_update_failed",
      "remote_update_verify_step",
      "remote_update_no_canonical_progress",
      "remote_update_received",
      "remote_update_verified",
      "update_ack_admission_advance_failed",
      "update_ack_admission_advance_ready",
      "update_ack_admission_checkpoint_ready",
      "update_ack_admission_checkpoint_start",
      "update_encoded",
      "update_push_start",
      "update_saved_ack",
      "update_saved_ack_failed",
      "workspace_directory_identity_rejected",
    ]);
    return (w.__refmdE2ESyncPerf ?? [])
      .filter((item) => {
        const event = (item as { event?: unknown }).event;
        return typeof event === "string" && relevantEvents.has(event);
      })
      .slice(-80);
  });
}

async function collectDocumentSyncState(page: Page, docId: string): Promise<unknown> {
  return page.evaluate((id) => {
    const state = window.__refmdGetDocumentSyncState?.(id) ?? null;
    if (!state) return null;
    return {
      activeSnapshotId: state.activeSnapshotId,
      autoSync: state.autoSync,
      candidates: state.candidates.map((candidate) => ({
        channelState: candidate.channelState,
        readOnly: candidate.readOnly,
        savedText: candidate.savedText,
        savedStateVector: candidate.savedStateVector,
        stateKey: candidate.stateKey,
        text: candidate.text,
      })),
      channelState: state.channelState,
      confirmedClocks: state.confirmedClocks,
      error: state.error,
      pendingUpdate: state.pendingUpdate,
      readOnly: state.readOnly,
      recentSaveEvents: state.recentSaveEvents,
      savedText: state.savedText,
      savedStateVector: state.savedStateVector,
      sending: state.sending,
      stateKey: state.stateKey,
      text: state.text,
      unsavedCanonicalText: state.unsavedCanonicalText,
    };
  }, docId);
}

async function collectDivergenceDiagnostics(
  label: string,
  docId: string,
  pages: { name: string; page: Page }[],
): Promise<string> {
  const diagnostics = await Promise.all(
    pages.map(async ({ name, page }) => ({
      name,
      editorText: await readEditorText(page).catch((error) =>
        `readEditorText failed: ${error instanceof Error ? error.message : String(error)}`,
      ).then((text) => text.slice(0, 500)),
      syncState: await collectDocumentSyncState(page, docId).catch((error) => ({
        error: `collectDocumentSyncState failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      })),
      clientLogs: await collectClientLogs(page).catch((error) => [
        `collectClientLogs failed: ${error instanceof Error ? error.message : String(error)}`,
      ]),
      syncPerf: await collectSyncPerf(page).catch((error) => [
        `collectSyncPerf failed: ${error instanceof Error ? error.message : String(error)}`,
      ]),
      url: page.url(),
    })),
  );
  return `${label}: ${JSON.stringify(diagnostics)}`;
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
      "initial_load_failed",
      "reconnect_failed",
      "connection_error",
      "sync gap detected",
      "too much recursion",
      "CodeMirror plugin crashed",
    ].some((needle) => message.includes(needle)),
  );
}

async function focusVisibleEditor(page: Page): Promise<void> {
  const panel = page.locator("[data-panel-id]").first();
  if (await panel.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await panel.click({ position: { x: 8, y: 8 } });
  }

  const codeMirror = page.locator(".cm-content").first();
  if (await codeMirror.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await codeMirror.click();
    return;
  }

  const proseMirror = page.locator(".ProseMirror").first();
  await expect(proseMirror).toBeVisible({ timeout: 15_000 });
  await proseMirror.click();
}

async function switchCurrentPaneToWysiwyg(page: Page): Promise<void> {
  if (await page.locator('.ProseMirror[contenteditable="true"]').isVisible().catch(() => false)) {
    return;
  }

  const trigger = page.locator('[data-slot="dropdown-menu-trigger"]').last();
  await expect(trigger).toBeVisible({ timeout: 10_000 });
  await trigger.click();
  const menuContent = page.locator('[data-slot="dropdown-menu-content"]');
  await expect(menuContent).toBeVisible({ timeout: 5_000 });
  await menuContent.locator('[data-slot="dropdown-menu-item"]', { hasText: "WYSIWYG" }).last().click();
  await expect(page.locator('.ProseMirror[contenteditable="true"]')).toBeVisible({
    timeout: 10_000,
  });
}

async function switchCurrentPaneToMarkdown(page: Page): Promise<void> {
  if (
    (await page.locator(".cm-content").isVisible().catch(() => false)) &&
    !(await page.locator('.ProseMirror[contenteditable="true"]').isVisible().catch(() => false))
  ) {
    return;
  }

  const trigger = page.locator('[data-slot="dropdown-menu-trigger"]').last();
  await expect(trigger).toBeVisible({ timeout: 10_000 });
  await trigger.click();
  const menuContent = page.locator('[data-slot="dropdown-menu-content"]');
  await expect(menuContent).toBeVisible({ timeout: 5_000 });
  const markdownOnly = menuContent.getByRole("menuitem", { name: "Markdown only" });
  if (await markdownOnly.isVisible({ timeout: 500 }).catch(() => false)) {
    await markdownOnly.click();
  } else {
    await menuContent
      .locator('[data-slot="dropdown-menu-item"]', { hasText: "Switch to Markdown" })
      .click();
  }
  await expect(page.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('.ProseMirror[contenteditable="true"]')).not.toBeVisible({
    timeout: 5_000,
  });
}

async function expectRemoteCursorVisible(
  page: Page,
  selector: string,
  label: string,
): Promise<void> {
  await expect
    .poll(
      async () => ({
        count: await page.locator(selector).count(),
        url: page.url(),
      }),
      {
        timeout: 15_000,
        message: `${label} remote cursor did not render`,
      },
    )
    .toMatchObject({ count: 1 });
  await expect(page.locator(selector).first(), `${label} remote cursor is hidden`).toBeVisible({
    timeout: 5_000,
  });
}

async function ensureEditorReady(page: Page, title: string): Promise<void> {
  const hasEditor = await page
    .locator(".cm-content, .ProseMirror")
    .first()
    .isVisible({ timeout: 15_000 })
    .catch(() => false);
  if (hasEditor) return;

  const hasDisconnectedPanels = await page
    .getByText("disconnected", { exact: true })
    .first()
    .isVisible({ timeout: 1_000 })
    .catch(() => false);
  if (hasDisconnectedPanels) {
    await page.goto("/dashboard");
    await waitForWorkspaceReady(page);
  }
  await openDocument(page, title);
}

async function loginForDeviceRegistration(page: Page, email: string): Promise<void> {
  await page.goto("/auth/login");
  await expect(page.locator("#email")).toBeVisible({ timeout: 30_000 });
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(TEST_PASSWORD);
  await page.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/devices\/register/, { timeout: 120_000 });

  const deadline = Date.now() + 120_000;

  while (Date.now() < deadline) {
    if (
      await page
        .getByText("Waiting for approval from an existing device")
        .isVisible({ timeout: 1_000 })
        .catch(() => false)
    ) {
      return;
    }

    const passwordPrompt = page.locator("#password-reentry-password, #reauth-password").first();
    if (await passwordPrompt.isVisible({ timeout: 1_000 }).catch(() => false)) {
      await passwordPrompt.fill(TEST_PASSWORD);
      await page.getByRole("button", { name: "Continue" }).click();
    }

    await page.waitForTimeout(E2E_DELAYS.poll);
  }

  const body = await page.locator("body").innerText().catch(() => "");
  throw new Error(`device registration did not reach approval wait: ${body.slice(0, 600)}`);
}

let ctxA: BrowserContext;
let ctxB: BrowserContext;
let pageA: Page;
let pageB: Page;
let email: string;
let documentId: string;

function currentDocumentId(page: Page): string {
  const match = new URL(page.url()).pathname.match(/^\/document\/([^/]+)$/);
  if (!match) throw new Error(`current path is not a document route: ${page.url()}`);
  return match[1];
}

async function waitForWritableDocumentSync(
  page: Page,
  docId: string,
  timeout = 60_000,
): Promise<void> {
  try {
    await expect
      .poll(
        () =>
          page.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, docId),
        {
          timeout,
          message: `document sync did not become writable for ${docId}`,
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
  } catch (error) {
    const logs = await collectClientLogs(page).catch(() => []);
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}; clientLogs=${JSON.stringify(logs)}`,
    );
  }
}

test.describe.serial("Single-User Multi-Device Sync", () => {
  test.beforeAll(async ({ browser }) => {
    ctxA = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
    ctxB = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
    await ctxA.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      const w = window as Window & { __refmdE2EClientLogs?: unknown[] };
      w.__refmdE2EClientLogs = [];
      window.addEventListener("refmd:client-log", (event) => {
        w.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
      });
    });
    await ctxB.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      const w = window as Window & { __refmdE2EClientLogs?: unknown[] };
      w.__refmdE2EClientLogs = [];
      window.addEventListener("refmd:client-log", (event) => {
        w.__refmdE2EClientLogs?.push((event as CustomEvent).detail);
      });
    });
    pageA = await ctxA.newPage();
    pageB = await ctxB.newPage();
  });

  test.afterAll(async () => {
    await ctxA.close();
    await ctxB.close();
  });

  test("approved second device stays synchronized through burst edits", async () => {
    test.setTimeout(E2E_TIMEOUTS.pluginInstall);

    await test.step("register on device A, create document, and type content", async () => {
      email = await registerAccount(pageA);
      await createDocument(pageA, "Multi Device Doc");
      await openDocument(pageA, "Multi Device Doc");
      documentId = currentDocumentId(pageA);
      await waitForWritableDocumentSync(pageA, documentId, 60_000);
      await pageA.waitForTimeout(E2E_DELAYS.syncSettle);

      await pageA.locator(".cm-content").click();
      await pageA.keyboard.insertText("From device A. ");
      await pageA.waitForTimeout(E2E_DELAYS.syncSettle);
    });

    await test.step("login on device B and approve from device A", async () => {
      await loginForDeviceRegistration(pageB, email);

      await expect(
        pageA.getByRole("button", { name: /Emojis Match.*Approve/i }),
      ).toBeVisible({ timeout: 120_000 });

      await pageA.getByRole("button", { name: /Emojis Match.*Approve/i }).click();

      await expect(pageB).toHaveURL(/dashboard/, { timeout: 120_000 });
      await waitForWorkspaceReady(pageB);
      await pageB.waitForTimeout(E2E_DELAYS.syncSettle);

      await expect(pageB.locator("aside").getByText("Multi Device Doc")).toBeVisible({
        timeout: 30_000,
      });
      await openDocument(pageB, "Multi Device Doc");
      await waitForWritableDocumentSync(pageB, documentId, 60_000);
    });

    await test.step("device B types and device A sees it", async () => {
      await ensureEditorReady(pageB, "Multi Device Doc");
      await typeInVisibleEditor(pageB, "From device B. ");
      await expectEditorTextContains(pageA, "From device B.", 60_000).catch(async (error) => {
        const diagnostics = await collectDivergenceDiagnostics(
          "device B edit did not appear on device A",
          documentId,
          [
            { name: "deviceA", page: pageA },
            { name: "deviceB", page: pageB },
          ],
        );
        throw new Error(`${error instanceof Error ? error.message : String(error)}; ${diagnostics}`);
      });
    });

    await test.step("same-user other-device session remains interactive", async () => {
      await ensureEditorReady(pageA, "Multi Device Doc");
      await ensureEditorReady(pageB, "Multi Device Doc");
      await expectEditorTextContains(pageA, "From device B.", 15_000);
      await expectEditorTextContains(pageB, "From device B.", 15_000);
    });

    await test.step("same-user awareness cursors cross Markdown and WYSIWYG modes", async () => {
      await ensureEditorReady(pageA, "Multi Device Doc");
      await ensureEditorReady(pageB, "Multi Device Doc");
      await switchCurrentPaneToMarkdown(pageA);
      await switchCurrentPaneToWysiwyg(pageB);
      await waitForWritableDocumentSync(pageA, documentId, 60_000);
      await waitForWritableDocumentSync(pageB, documentId, 60_000);

      const markdown = pageA.locator(".cm-content").first();
      await expect(markdown).toBeVisible({ timeout: 10_000 });
      await markdown.click();
      await pageA.keyboard.press(process.platform === "darwin" ? "Meta+End" : "Control+End");
      await pageA.keyboard.press("ArrowLeft");
      await pageA.keyboard.press("ArrowRight");
      await expectRemoteCursorVisible(pageB, ".ProseMirror-yjs-cursor", "Markdown to WYSIWYG");

      const wysiwyg = pageB.locator('.ProseMirror[contenteditable="true"]').first();
      await expect(wysiwyg).toBeVisible({ timeout: 10_000 });
      await wysiwyg.click();
      await pageB.keyboard.press(process.platform === "darwin" ? "Meta+End" : "Control+End");
      await pageB.keyboard.press("ArrowLeft");
      await pageB.keyboard.press("ArrowRight");
      await expectRemoteCursorVisible(pageA, ".cm-ySelectionCaret", "WYSIWYG to Markdown");
      await switchCurrentPaneToMarkdown(pageB);
    });

    await test.step("same-user approved device concurrent edits survive snapshot rotation", async () => {
      const diagnostics = collectSyncDiagnostics([pageA, pageB]);
      try {
        await ensureEditorReady(pageA, "Multi Device Doc");
        await ensureEditorReady(pageB, "Multi Device Doc");

        for (let i = 0; i < 40; i += 1) {
          await waitForWritableDocumentSync(pageA, documentId, 90_000);
          await waitForWritableDocumentSync(pageB, documentId, 90_000);
          await Promise.all([
            appendDocumentTextViaSyncHook(pageA, documentId, `threshold-a-${i}\n`),
            appendDocumentTextViaSyncHook(pageB, documentId, `threshold-b-${i}\n`),
          ]);
          await expectDocumentTextContains(pageA, documentId, `threshold-b-${i}`, 90_000);
          await expectDocumentTextContains(pageB, documentId, `threshold-a-${i}`, 90_000);
          await expectMarkdownEditorsConverged(pageA, pageB, documentId, 30_000);
        }

        for (let i = 0; i < 12; i += 1) {
          await waitForWritableDocumentSync(pageA, documentId, 90_000);
          await waitForWritableDocumentSync(pageB, documentId, 90_000);
          const markerA = `keyboard-a-${i}-${crypto.randomUUID()}`;
          const markerB = `keyboard-b-${i}-${crypto.randomUUID()}`;
          await Promise.all([
            typeMarkdownMarkerAtDocumentEnd(pageA, markerA),
            typeMarkdownMarkerAtDocumentEnd(pageB, markerB),
          ]);
          await expectDocumentTextContainsWithDiagnostics(
            pageA,
            documentId,
            markerB,
            90_000,
            `device A did not receive ${markerB}`,
            [
              { name: "deviceA", page: pageA },
              { name: "deviceB", page: pageB },
            ],
          );
          await expectDocumentTextContainsWithDiagnostics(
            pageB,
            documentId,
            markerA,
            90_000,
            `device B did not receive ${markerA}`,
            [
              { name: "deviceA", page: pageA },
              { name: "deviceB", page: pageB },
            ],
          );
          await expectMarkdownEditorsConverged(pageA, pageB, documentId, 30_000);
        }

        await expectMarkdownEditorsConverged(pageA, pageB, documentId, 30_000);
        await waitForWritableDocumentSync(pageA, documentId, 90_000);
        await waitForWritableDocumentSync(pageB, documentId, 90_000);

        const convergedTextBeforeReload = await readMarkdownEditorText(pageA, documentId);
        await pageB.reload({ waitUntil: "domcontentloaded" });
        await ensureEditorReady(pageB, "Multi Device Doc");
        await expectDocumentTextContains(pageB, documentId, "keyboard-a-11", 60_000);
        await waitForWritableDocumentSync(pageB, documentId, 90_000);
        await waitForWritableDocumentSync(pageA, documentId, 90_000);
        await expectMarkdownEditorsConverged(pageA, pageB, documentId, 30_000);
        await expect
          .poll(() => readMarkdownEditorText(pageB, documentId), {
            timeout: 60_000,
            message: "reloaded device did not preserve the converged document text",
          })
          .toBe(convergedTextBeforeReload);

        await typeInVisibleEditor(pageA, "owner-after-device-burst");
        await expectDocumentTextContains(pageA, documentId, "owner-after-device-burst", 10_000).catch(
          async (error) => {
            const state = await collectDivergenceDiagnostics("owner edit did not apply on device A", documentId, [
              { name: "deviceA", page: pageA },
              { name: "deviceB", page: pageB },
            ]);
            throw new Error(`${error instanceof Error ? error.message : String(error)}; ${state}`);
          },
        );
        await expectDocumentTextContains(pageB, documentId, "owner-after-device-burst", 90_000).catch(
          async (error) => {
            const state = await collectDivergenceDiagnostics(
              "owner edit did not propagate to device B",
              documentId,
              [
                { name: "deviceA", page: pageA },
                { name: "deviceB", page: pageB },
              ],
            );
            throw new Error(`${error instanceof Error ? error.message : String(error)}; ${state}`);
          },
        );
        await expectMarkdownEditorsConverged(pageA, pageB, documentId, 30_000);

        expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
      } finally {
        diagnostics.stop();
      }
    });
  });
});
