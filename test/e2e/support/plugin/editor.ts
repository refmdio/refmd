import {
  expect,
  type Page,
} from "@playwright/test";
import { expectEditorTextContains } from "../editor";
import { E2E_DELAYS } from "../timeouts";
import { safePageFrames } from "./diagnostics";
import { pluginRuntimeDiagnostic } from "./diagnostics";
import { PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS } from "./types";

export async function replaceEditorMarkdown(
  page: Page,
  markdown: string,
  expectedSnippet = "```refmd-renderer-demo",
): Promise<void> {
  const documentId = currentDocumentId(page);
  const accepted = await page
    .waitForFunction(
      ([id, value]) => window.__refmdSetEditorValueForDocument?.(id, value) === true,
      [documentId, markdown] as const,
      { timeout: 60_000 },
    )
    .then(() => true)
    .catch(async (error) => {
      throw new Error(
        `document editor test hook did not accept the markdown value:\n${await pluginRuntimeDiagnostic(
          page,
        )}\n${String(error)}`,
      );
    });
  if (!accepted) {
    throw new Error(
      `document editor test hook did not accept the markdown value:\n${await pluginRuntimeDiagnostic(
        page,
      )}`,
    );
  }
  const editor = page.locator(".cm-content, .ProseMirror").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await expectEditorTextContains(page, expectedSnippet, 30_000);
}

export async function flushCurrentDocumentSync(page: Page): Promise<void> {
  const documentId = currentDocumentId(page);
  await expect
    .poll(
      () =>
        page.evaluate(
          async (id) => (await window.__refmdFlushDocumentSync?.(id)) === true,
          documentId,
        ),
      {
        timeout: 60_000,
        message: "document sync flush did not complete",
      },
    )
    .toBe(true);
  await expect
    .poll(
      () =>
        page.evaluate((id) => {
          const state = window.__refmdGetDocumentSyncState?.(id);
          return state?.unsavedCanonicalText === false && state?.pendingSave === false;
        }, documentId),
      {
        timeout: 60_000,
        message: "document sync state did not settle after flush",
      },
    )
    .toBe(true);
}

export async function selectAllEditorText(page: Page): Promise<void> {
  const editor = page.locator(".cm-content, .ProseMirror").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click();
  await page.keyboard.press("Control+A");
  const documentId = currentDocumentId(page);
  await expect
    .poll(
      () =>
        page.evaluate((id) => {
          const testWindow = window as typeof window & {
            __refmdSetEditorSelectionForDocument?: (
              documentId: string,
              anchorOffset: number,
              headOffset: number,
            ) => boolean;
            __refmdGetDocumentText?: (documentId: string) => string | null;
          };
          const text = testWindow.__refmdGetDocumentText?.(id) ?? "";
          return testWindow.__refmdSetEditorSelectionForDocument?.(id, 0, text.length) === true;
        }, documentId),
      {
        timeout: 30_000,
        message: "document editor test hook did not select editor text",
      },
    )
    .toBe(true);
}

export async function openEditorContextMenu(page: Page): Promise<void> {
  const editor = page.locator(".cm-content, .ProseMirror").first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  const box = await editor.boundingBox();
  if (!box) throw new Error("editor bounding box was not available");
  await editor.dispatchEvent("contextmenu", {
    bubbles: true,
    cancelable: true,
    clientX: box.x + Math.min(120, box.width / 2),
    clientY: box.y + Math.min(80, box.height / 2),
  });
}

export async function runEditorContribution(page: Page, title: string): Promise<void> {
  let lastError: unknown = null;
  await expect
    .poll(
      async () => {
        try {
          await openEditorContextMenu(page);
          const action = page.getByRole("button", { name: title });
          await expect(action).toBeVisible({ timeout: 5_000 });
          await action.click({ timeout: 5_000 });
          return true;
        } catch (error) {
          lastError = error;
          await page.keyboard.press("Escape").catch(() => {});
          await page.waitForTimeout(E2E_DELAYS.poll);
          return false;
        }
      },
      {
        timeout: 90_000,
        message: `editor contribution ${title} was not available: ${String(lastError)}`,
      },
    )
    .toBe(true);
}

export async function runCommandPaletteCommand(page: Page, title: string): Promise<void> {
  await page.keyboard.press("Control+P");
  const commandInput = page.locator('input[placeholder="Type a command..."]');
  const commandDialog = page.locator('[role="dialog"]').filter({ has: commandInput });
  await expect(commandInput).toBeVisible({ timeout: 30_000 });
  await commandInput.fill(title);
  const commandItem = commandDialog.locator('[data-slot="command-item"]', { hasText: title }).first();
  await expect(commandItem).toBeVisible({ timeout: 30_000 });
  await commandItem.click();
  await expect(commandDialog).toHaveCount(0, { timeout: 10_000 });
}

export async function expectCommandPaletteCommandAbsent(page: Page, title: string): Promise<void> {
  await page.keyboard.press("Control+P");
  const commandInput = page.locator('input[placeholder="Type a command..."]');
  const commandDialog = page.locator('[role="dialog"]').filter({ has: commandInput });
  await expect(commandInput).toBeVisible({ timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
  await commandInput.fill(title);
  await expect(commandDialog.getByText(title, { exact: true })).toHaveCount(0, {
    timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
  });
  await page.keyboard.press("Escape");
  await expect(commandDialog).toHaveCount(0, { timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS });
}

export function currentDocumentId(page: Page): string {
  const url = new URL(page.url());
  const match = url.pathname.match(/\/document\/([^/]+)/);
  if (!match?.[1]) throw new Error(`document id not found in URL: ${url.pathname}`);
  return match[1];
}

export async function editorDemoFrameState(page: Page): Promise<{
  status: string | null;
  frameCount: number;
  frameTexts: string[];
}> {
  const frameTexts: string[] = [];
  let status: string | null = null;
  for (const frame of safePageFrames(page)) {
    const state = await frame
      .evaluate(() => {
        const bodyText = document.body?.innerText ?? "";
        return {
          bodyText,
          status: document.querySelector('[data-role="status"]')?.textContent ?? null,
        };
      })
      .catch(() => null);
    if (!state?.bodyText.includes("RefMD Editor Demo Plugin")) continue;
    frameTexts.push(state.bodyText.slice(0, 500));
    status = state.status;
  }
  return { status, frameCount: frameTexts.length, frameTexts };
}
