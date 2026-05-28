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
import { expectEditorTextContains } from "../../support/editor";
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

async function typeLineBurst(page: Page, prefix: string, count: number): Promise<void> {
  await focusVisibleEditor(page);
  await page.keyboard.press("Control+End");

  for (let i = 0; i < count; i += 1) {
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(`${prefix}-${i}`);
    await page.waitForTimeout(E2E_DELAYS.inputPropagation);
  }
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
    test.setTimeout(E2E_TIMEOUTS.multiDevice);

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
        const logs = await collectClientLogs(pageA);
        throw new Error(`${error instanceof Error ? error.message : String(error)}; pageA logs=${JSON.stringify(logs)}`);
      });
    });

    await test.step("same-user other-device session remains interactive", async () => {
      await ensureEditorReady(pageA, "Multi Device Doc");
      await ensureEditorReady(pageB, "Multi Device Doc");
      await expectEditorTextContains(pageA, "From device B.", 15_000);
      await expectEditorTextContains(pageB, "From device B.", 15_000);
    });

    await test.step("same-user approved device burst edits remain synchronized", async () => {
      const diagnostics = collectSyncDiagnostics([pageA, pageB]);
      try {
        await ensureEditorReady(pageA, "Multi Device Doc");
        await ensureEditorReady(pageB, "Multi Device Doc");

        await typeLineBurst(pageB, "device-b-burst", 80);
        await expectEditorTextContains(pageA, "device-b-burst-79", 90_000);

        await pageB.reload({ waitUntil: "domcontentloaded" });
        await ensureEditorReady(pageB, "Multi Device Doc");
        await expectEditorTextContains(pageB, "device-b-burst-79", 60_000);
        await waitForWritableDocumentSync(pageB, documentId, 90_000);
        await waitForWritableDocumentSync(pageA, documentId, 90_000);

        await typeInVisibleEditor(pageA, "owner-after-device-burst");
        await expectEditorTextContains(pageB, "owner-after-device-burst", 90_000);

        expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
      } finally {
        diagnostics.stop();
      }
    });
  });
});
