import {
  expect,
  test,
  type BrowserContext,
  type Locator,
  type Page,
  type WebSocketRoute,
} from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { createDocument, openContextMenu, openDocument } from "../../support/documents";
import { expectEditorTextContains, readEditorText } from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

const DOC_TITLE = "Anonymous Edit Share Sync";
const LOGGED_IN_DOC_TITLE = "Logged In Share Edit Sync";
const SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE =
  /\/share\/(?:d\/)?[^/#]+(?:#(?:cap=[A-Za-z0-9_-]{43}&wpb=[A-Za-z0-9_-]{43}(?:&s=[A-Za-z0-9_-]{22})?|s=[A-Za-z0-9_-]{22}))?$/;
const SHARE_DOCUMENT_ROUTE_RE = /\/share\/d\/[^/#]+(?:#.*)?$/;
const SHARE_LINK_CREATION_TIMEOUT_MS = 120_000;
const REALTIME_TEXT_LATENCY_MS = 1_000;
const SHARE_ROUTE_ERROR_TEXTS = [
  "Share document not found.",
  "Share not found.",
  "Invalid share document route.",
  "Invalid share link.",
] as const;

async function newStrictShareContext(
  browser: Parameters<typeof newE2EContext>[0],
  options: Parameters<typeof newE2EContext>[1] = {},
): Promise<BrowserContext> {
  return newE2EContext(browser, {
    ...options,
    bypassCSP: false,
  });
}

function currentDocumentId(page: Page): string {
  const path = new URL(page.url()).pathname;
  const match = path.match(/^\/document\/([^/]+)$/) ?? path.match(/^\/share\/d\/([^/]+)$/);
  if (!match) throw new Error(`current path is not a document route: ${page.url()}`);
  return match[1];
}

function currentDocumentIdOrNull(page: Page): string | null {
  try {
    return currentDocumentId(page);
  } catch {
    return null;
  }
}

async function waitForDocumentSyncReady(page: Page): Promise<void> {
  const documentId = currentDocumentId(page);
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
  } catch (error) {
    const state = await page.evaluate(
      (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
      documentId,
    );
    throw new Error(
      `document sync did not become ready: ${JSON.stringify(state)}\n${String(error)}`,
    );
  }
}

async function expectLastJoinMode(page: Page, expectedMode: "complete" | "delta"): Promise<void> {
  const documentId = currentDocumentId(page);
  try {
    await expect
      .poll(
        async () =>
          page.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.lastJoinMode ?? null,
            documentId,
          ),
        {
          timeout: 60_000,
          message: `document did not join with ${expectedMode} mode`,
        },
      )
      .toBe(expectedMode);
  } catch (error) {
    const state = await page.evaluate(
      (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
      documentId,
    );
    throw new Error(
      `document did not join with ${expectedMode} mode: ${JSON.stringify(state)}\n${String(error)}`,
    );
  }
}

async function waitForDocumentWriteSessionReady(
  page: Page,
  options: { allowGenesisSnapshot?: boolean; requireWriteSessionReady?: boolean } = {},
): Promise<void> {
  const documentId = currentDocumentId(page);
  const states: unknown[] = [];
  const isWritableReady = (state: unknown): boolean => {
    if (typeof state !== "object" || state === null) return false;
    const item = state as Record<string, unknown>;
    const commonReady =
      item.channelState === "joined" &&
      item.error === null &&
      item.initialized === true &&
      item.pendingSave === false &&
      item.pendingSnapshot === false &&
      item.pendingUpdate === false &&
      item.readOnly === false &&
      item.reconnecting === false &&
      item.sending === false &&
      item.syncPaused === false &&
      item.unsavedCanonicalText === false;
    if (!commonReady) return false;
    if (!options.requireWriteSessionReady) return true;
    if (item.writeSessionReady === true) return true;
    return options.allowGenesisSnapshot === true && item.activeSnapshotId === null;
  };
  try {
    await expect
      .poll(
        async () => {
          const state = await page.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            documentId,
          );
          states.push(state);
          return isWritableReady(state);
        },
        {
          timeout: 60_000,
          message: "document write session did not become ready",
        },
      )
      .toBe(true);
  } catch (error) {
    throw new Error(
      [
        `document writable sync state did not become ready: ${String(error)}`,
        `recent-states: ${JSON.stringify(states.slice(-8))}`,
        `sync-perf: ${JSON.stringify(await readSyncPerf(page))}`,
      ].join("\n"),
    );
  }
}

async function flushDocumentSync(page: Page): Promise<void> {
  await page.bringToFront();
  const routeDocumentId = currentDocumentId(page);
  const documentId = await page
    .evaluate((id) => window.__refmdGetDocumentSyncState?.(id)?.documentId ?? id, routeDocumentId)
    .catch(() => routeDocumentId);
  const flushed = await page
    .evaluate(
      async ({ id, timeoutMs }) => {
        const flush =
          (
            window as Window & {
              __refmdFlushDocumentSync?: (documentId: string) => Promise<boolean>;
            }
          ).__refmdFlushDocumentSync?.(id) ?? Promise.resolve(false);
        return Promise.race([
          flush,
          new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), timeoutMs)),
        ]);
      },
      { id: documentId, timeoutMs: 20_000 },
    )
    .catch((error) => `error:${String(error)}`);
  if (flushed === true) return;
  const [state, perf] = await Promise.all([
    page.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, documentId),
    readSyncPerf(page),
  ]);
  throw new Error(
    `document sync flush did not complete: ${String(flushed)}\nstate=${JSON.stringify(
      state,
    )}\nsyncPerf=${JSON.stringify(perf)}`,
  );
}

async function waitForVisibleEditorTextToken(
  page: Page,
  text: string,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const startedAt = Date.now();
  return waitForVisibleEditorTextTokenFrom(page, text, startedAt, timeoutMs);
}

async function waitForVisibleEditorTextTokenFrom(
  page: Page,
  text: string,
  startedAt: number,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  await page.bringToFront();
  await expect
    .poll(async () => (await readVisibleEditorSurfaceText(page)).includes(text), {
      interval: 25,
      timeout: timeoutMs,
      message: `visible editor text did not contain ${text} within ${timeoutMs}ms`,
    })
    .toBe(true);
  return Date.now() - startedAt;
}

async function readVisibleEditorSurfaceText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const remoteCursorLabelRe =
      /\u2060+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\u2060*/gi;
    const isVisible = (node: HTMLElement) => {
      const rect = node.getBoundingClientRect();
      const style = window.getComputedStyle(node);
      return (
        rect.width > 0 &&
        rect.height > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        style.opacity !== "0"
      );
    };
    const normalize = (value: string | null | undefined) =>
      (value || "").replace(remoteCursorLabelRe, "");
    const fragments: string[] = [];

    for (const editor of document.querySelectorAll<HTMLElement>(
      '.cm-content[contenteditable="true"]',
    )) {
      if (!isVisible(editor)) continue;
      const lines = [...editor.querySelectorAll<HTMLElement>(".cm-line")].map((line) =>
        normalize(line.textContent),
      );
      fragments.push(lines.length > 0 ? lines.join("\n") : normalize(editor.textContent));
    }
    for (const editor of document.querySelectorAll<HTMLElement>(
      [
        ".ProseMirror",
        '[data-testid="markdown-preview"]',
        '[role="textbox"][contenteditable="true"]',
        "textarea",
      ].join(", "),
    )) {
      if (!isVisible(editor)) continue;
      fragments.push(normalize(editor.innerText || editor.textContent));
    }
    for (const preview of document.querySelectorAll<HTMLElement>(
      '[data-refmd-content-preview="true"]',
    )) {
      if (!isVisible(preview)) continue;
      fragments.push(normalize(preview.innerText || preview.textContent));
    }

    const text = fragments.filter((fragment) => fragment.trim().length > 0).join("\n");
    if (text.trim().length === 0) {
      throw new Error("no visible editor surface text was available");
    }
    return text;
  });
}

async function readVisibleMarkdownEditorText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const isVisible = (node: HTMLElement) => {
      const rect = node.getBoundingClientRect();
      const style = window.getComputedStyle(node);
      return (
        rect.width > 0 &&
        rect.height > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        style.opacity !== "0"
      );
    };
    const editor = [
      ...document.querySelectorAll<HTMLElement>('.cm-content[contenteditable="true"]'),
    ].find(isVisible);
    if (!editor) throw new Error("markdown editor content element was not mounted");
    const remoteCursorLabelRe =
      /\u2060+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\u2060*/gi;
    return [...editor.querySelectorAll<HTMLElement>(".cm-line")]
      .map((line) => (line.textContent || "").replace(remoteCursorLabelRe, ""))
      .join("\n");
  });
}

async function readRegisteredEditorValues(page: Page): Promise<
  Array<{
    focused: boolean;
    lineCount: number;
    panelId: string;
    value: string;
  }>
> {
  const documentId = currentDocumentId(page);
  return page.evaluate((id) => window.__refmdGetEditorValuesForDocument?.(id) ?? [], documentId);
}

async function expectRegisteredEditorValuesEqual(
  page: Page,
  expectedText: string,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const startedAt = Date.now();
  await expect
    .poll(
      async () => {
        const values = await readRegisteredEditorValues(page);
        return {
          ok: values.length > 0 && values.every((entry) => entry.value === expectedText),
          values,
          mismatches: values.filter((entry) => entry.value !== expectedText),
        };
      },
      {
        interval: 25,
        timeout: timeoutMs,
        message: `registered editor values did not exactly match ${JSON.stringify(expectedText)}`,
      },
    )
    .toEqual({
      ok: true,
      values: expect.any(Array),
      mismatches: [],
    });
  return Date.now() - startedAt;
}

async function expectRegisteredEditorValuesEqualSince(
  page: Page,
  expectedText: string,
  startedAt: number,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const deadline = startedAt + timeoutMs;
  const observations: Array<{
    elapsedMs: number;
    values: Array<{ panelId: string; value: string }>;
  }> = [];

  while (Date.now() <= deadline) {
    const values = await readRegisteredEditorValues(page);
    const elapsedMs = Date.now() - startedAt;
    observations.push({
      elapsedMs,
      values: values.map(({ panelId, value }) => ({ panelId, value })),
    });
    if (values.length > 0 && values.every((entry) => entry.value === expectedText)) {
      return elapsedMs;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  throw new Error(
    `registered editor values did not exactly match ${JSON.stringify(
      expectedText,
    )} within ${timeoutMs}ms from edit start: ${JSON.stringify({
      last: observations.at(-1),
      observations: observations.slice(-20),
    })}`,
  );
}

function expectedRenderedMarkdownTokens(markdownText: string): string[] {
  return markdownText
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) =>
      line
        .trim()
        .replace(/^#{1,6}\s+/, "")
        .replace(/^[-*+]\s+/, "")
        .replace(/^\d+\.\s+/, "")
        .trim(),
    )
    .filter((line) => line.length > 0);
}

async function readVisibleProseMirrorText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const isVisible = (node: HTMLElement) => {
      const rect = node.getBoundingClientRect();
      const style = window.getComputedStyle(node);
      return (
        rect.width > 0 &&
        rect.height > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        style.opacity !== "0"
      );
    };
    const editor = [
      ...document.querySelectorAll<HTMLElement>('.ProseMirror, [data-testid="markdown-preview"]'),
    ].find(isVisible);
    if (!editor) throw new Error("WYSIWYG preview content element was not mounted");
    return editor.innerText || editor.textContent || "";
  });
}

async function expectVisibleProseMirrorContainsMarkdownText(
  page: Page,
  expectedMarkdownText: string,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const startedAt = Date.now();
  return expectVisibleProseMirrorContainsMarkdownTextSince(
    page,
    expectedMarkdownText,
    startedAt,
    timeoutMs,
  );
}

async function expectVisibleProseMirrorContainsMarkdownTextSince(
  page: Page,
  expectedMarkdownText: string,
  startedAt: number,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const tokens = expectedRenderedMarkdownTokens(expectedMarkdownText);
  const deadline = startedAt + timeoutMs;
  const observations: Array<{
    elapsedMs: number;
    missing: string[];
    rendered?: string;
    error?: string;
  }> = [];

  while (Date.now() <= deadline) {
    try {
      const renderedText = (await readVisibleProseMirrorText(page)).replace(/\s+/g, " ").trim();
      const missing = tokens.filter(
        (token) => !renderedText.includes(token.replace(/\s+/g, " ").trim()),
      );
      const elapsedMs = Date.now() - startedAt;
      observations.push({ elapsedMs, missing, rendered: renderedText.slice(0, 1000) });
      if (missing.length === 0) return elapsedMs;
    } catch (error) {
      observations.push({
        elapsedMs: Date.now() - startedAt,
        missing: tokens,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  throw new Error(
    `visible ProseMirror text did not contain all rendered tokens from ${JSON.stringify(
      expectedMarkdownText,
    )} within ${timeoutMs}ms from edit start: ${JSON.stringify({
      last: observations.at(-1),
      observations: observations.slice(-20),
    })}`,
  );
}

async function readLatencyVisibleEditorText(page: Page): Promise<string> {
  return readVisibleEditorSurfaceText(page).catch(() => readEditorText(page));
}

async function expectVisibleMarkdownEditorTextEquals(
  page: Page,
  expectedText: string,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const startedAt = Date.now();
  await expect
    .poll(() => readVisibleMarkdownEditorText(page), {
      interval: 25,
      timeout: timeoutMs,
      message: `visible markdown editor text did not exactly match ${JSON.stringify(
        expectedText,
      )} within ${timeoutMs}ms`,
    })
    .toBe(expectedText);
  return Date.now() - startedAt;
}

async function expectVisibleMarkdownEditorTextEqualsSince(
  page: Page,
  expectedText: string,
  startedAt: number,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  return pollTextSince({
    label: "visible markdown editor text",
    page,
    expectedText,
    startedAt,
    timeoutMs,
    read: readVisibleMarkdownEditorText,
  });
}

async function expectDocumentStateTextEquals(
  page: Page,
  expectedText: string,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const startedAt = Date.now();
  await expect
    .poll(
      async () => {
        const documentId = currentDocumentId(page);
        const state = await page.evaluate(
          (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
          documentId,
        );
        if (typeof state !== "object" || state === null) return null;
        return (state as { text?: unknown }).text ?? null;
      },
      {
        interval: 25,
        timeout: timeoutMs,
        message: `document sync state text did not exactly match ${JSON.stringify(
          expectedText,
        )} within ${timeoutMs}ms`,
      },
    )
    .toBe(expectedText);
  return Date.now() - startedAt;
}

async function expectDocumentStateTextEqualsSince(
  page: Page,
  expectedText: string,
  startedAt: number,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  return pollTextSince({
    label: "document sync state text",
    page,
    expectedText,
    startedAt,
    timeoutMs,
    read: readDocumentSyncStateText,
  });
}

async function readDocumentSyncStateText(page: Page): Promise<string | null> {
  const documentId = currentDocumentId(page);
  const state = await page.evaluate(
    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
    documentId,
  );
  if (typeof state !== "object" || state === null) return null;
  const text = (state as { text?: unknown }).text;
  return typeof text === "string" ? text : null;
}

async function readDocumentSavedStateText(page: Page): Promise<string | null> {
  const documentId = currentDocumentId(page);
  const state = await page.evaluate(
    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
    documentId,
  );
  if (typeof state !== "object" || state === null) return null;
  const text = (state as { savedText?: unknown }).savedText;
  return typeof text === "string" ? text : null;
}

async function expectDocumentSavedStateTextEquals(
  page: Page,
  expectedText: string,
  timeoutMs = REALTIME_TEXT_LATENCY_MS,
): Promise<number> {
  const startedAt = Date.now();
  await expect
    .poll(() => readDocumentSavedStateText(page), {
      interval: 25,
      timeout: timeoutMs,
      message: `document saved state text did not exactly match ${JSON.stringify(expectedText)}`,
    })
    .toBe(expectedText);
  return Date.now() - startedAt;
}

async function pollTextSince(params: {
  label: string;
  page: Page;
  expectedText: string;
  startedAt: number;
  timeoutMs: number;
  read: (page: Page) => Promise<string | null>;
}): Promise<number> {
  const deadline = params.startedAt + params.timeoutMs;
  const observations: Array<{ elapsedMs: number; value: string | null; error?: string }> = [];

  while (Date.now() <= deadline) {
    try {
      const value = await params.read(params.page);
      const elapsedMs = Date.now() - params.startedAt;
      observations.push({ elapsedMs, value });
      if (value === params.expectedText) return elapsedMs;
    } catch (error) {
      observations.push({
        elapsedMs: Date.now() - params.startedAt,
        value: null,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }

  const last = observations.at(-1);
  throw new Error(
    `${params.label} did not exactly match ${JSON.stringify(
      params.expectedText,
    )} within ${params.timeoutMs}ms from edit start: ${JSON.stringify({
      last,
      observations: observations.slice(-20),
    })}`,
  );
}

async function logExactTextSyncDiagnostics(
  label: string,
  ownerPage: Page,
  guestPage: Page,
): Promise<void> {
  await Promise.all([ownerPage.waitForTimeout(3_000), guestPage.waitForTimeout(3_000)]);
  const ownerDocumentId = currentDocumentId(ownerPage);
  const guestDocumentId = currentDocumentId(guestPage);
  const [ownerVisible, guestVisible, ownerState, guestState, ownerPerf, guestPerf] =
    await Promise.all([
      readVisibleMarkdownEditorText(ownerPage).catch(String),
      readVisibleMarkdownEditorText(guestPage).catch(String),
      ownerPage.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, ownerDocumentId),
      guestPage.evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, guestDocumentId),
      readSyncPerf(ownerPage),
      readSyncPerf(guestPage),
    ]);
  console.log(
    `[share-exact-existing-line-diagnostic] ${label} ${JSON.stringify({
      ownerVisible,
      guestVisible,
      ownerState,
      guestState,
      ownerPerf,
      guestPerf,
    })}`,
  );
}

async function expectRealtimeTextPropagation(
  senderPage: Page,
  receiverPage: Page,
  text: string,
): Promise<void> {
  await waitForDocumentWriteSessionReady(senderPage, { requireWriteSessionReady: true });
  await waitForDocumentWriteSessionReady(receiverPage, { requireWriteSessionReady: true });
  const focused = await focusAnyRealEditorAtEnd(senderPage, "realtime sender", {
    appendNewline: false,
  });
  const { insertedAt, localMutation } = await insertFocusedEditorTextAndStartLatencyClock(
    senderPage,
    focused.editor,
    `\n${text}`,
    text,
    focused.label,
  );
  const received = waitForVisibleEditorTextTokenFrom(receiverPage, text, insertedAt).catch(
    async (error) => {
      await receiverPage.waitForTimeout(2_000);
      const senderDocumentId = currentDocumentId(senderPage);
      const receiverDocumentId = currentDocumentId(receiverPage);
      const [senderState, receiverState, senderPerf, receiverPerf, receiverStateText] =
        await Promise.all([
          senderPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            senderDocumentId,
          ),
          receiverPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            receiverDocumentId,
          ),
          readSyncPerf(senderPage),
          readSyncPerf(receiverPage),
          receiverPage.evaluate(
            (id) => window.__refmdGetDocumentText?.(id) ?? null,
            receiverDocumentId,
          ),
        ]);
      const receiverVisibleText = await readLatencyVisibleEditorText(receiverPage);
      throw new Error(
        [
          `realtime visible text propagation failed for ${text}: ${String(error)}`,
          `sender-state: ${JSON.stringify(senderState)}`,
          `receiver-state: ${JSON.stringify(receiverState)}`,
          `receiver-visible-has-text-after-diagnostic-wait: ${JSON.stringify(
            receiverVisibleText.includes(text),
          )}`,
          `receiver-state-has-text-after-diagnostic-wait: ${JSON.stringify(
            receiverStateText?.includes(text) ?? false,
          )}`,
          `sender-sync-perf: ${JSON.stringify(senderPerf)}`,
          `receiver-sync-perf: ${JSON.stringify(receiverPerf)}`,
        ].join("\n"),
      );
    },
  );
  await localMutation;
  const elapsedMs = await received;
  expect(elapsedMs).toBeLessThanOrEqual(REALTIME_TEXT_LATENCY_MS);
  console.log(`[share-realtime-visible] text=${text} elapsedMs=${Math.round(elapsedMs)}`);
  await flushDocumentSync(senderPage);
  await waitForDocumentSyncReady(senderPage);
  await waitForDocumentSyncReady(receiverPage);
}

async function expectRealtimeTextPropagationViaEditorInput(
  senderPage: Page,
  receiverPage: Page,
  text: string,
): Promise<void> {
  await waitForDocumentWriteSessionReady(senderPage, { requireWriteSessionReady: true });
  await waitForDocumentWriteSessionReady(receiverPage, { requireWriteSessionReady: true });
  const focused = await focusAnyRealEditorAtEnd(senderPage, "realtime editor sender", {
    appendNewline: false,
  });
  const { insertedAt, localMutation } = await insertFocusedEditorTextAndStartLatencyClock(
    senderPage,
    focused.editor,
    `\n${text}`,
    text,
    focused.label,
  );
  const received = waitForVisibleEditorTextTokenFrom(receiverPage, text, insertedAt).catch(
    async (error) => {
      await receiverPage.waitForTimeout(2_000);
      const senderDocumentId = currentDocumentId(senderPage);
      const receiverDocumentId = currentDocumentId(receiverPage);
      const [senderState, receiverState, senderPerf, receiverPerf, receiverStateText] =
        await Promise.all([
          senderPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            senderDocumentId,
          ),
          receiverPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            receiverDocumentId,
          ),
          readSyncPerf(senderPage),
          readSyncPerf(receiverPage),
          receiverPage.evaluate(
            (id) => window.__refmdGetDocumentText?.(id) ?? null,
            receiverDocumentId,
          ),
        ]);
      const receiverVisibleText = await readLatencyVisibleEditorText(receiverPage);
      throw new Error(
        [
          `realtime editor input visible propagation failed for ${text}: ${String(error)}`,
          `sender-state: ${JSON.stringify(senderState)}`,
          `receiver-state: ${JSON.stringify(receiverState)}`,
          `receiver-visible-has-text-after-diagnostic-wait: ${JSON.stringify(
            receiverVisibleText.includes(text),
          )}`,
          `receiver-state-has-text-after-diagnostic-wait: ${JSON.stringify(
            receiverStateText?.includes(text) ?? false,
          )}`,
          `sender-sync-perf: ${JSON.stringify(senderPerf)}`,
          `receiver-sync-perf: ${JSON.stringify(receiverPerf)}`,
        ].join("\n"),
      );
    },
  );
  await localMutation;
  const elapsedMs = await received;
  expect(elapsedMs).toBeLessThanOrEqual(REALTIME_TEXT_LATENCY_MS);
  console.log(`[share-realtime-editor-visible] text=${text} elapsedMs=${Math.round(elapsedMs)}`);
  await flushDocumentSync(senderPage);
  await waitForDocumentSyncReady(senderPage);
  await waitForDocumentSyncReady(receiverPage);
}

function collectSyncDiagnostics(pages: Page[]): {
  messages: string[];
  stop: () => void;
} {
  const messages: string[] = [];
  const handlers = pages.map((page) => {
    const consoleHandler = (msg: { type: () => string; text: () => string }) => {
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
    const responseHandler = (response: { status: () => number; url: () => string }) => {
      const status = response.status();
      if (status >= 400) {
        messages.push(`response ${status} ${response.url()}`);
      }
    };
    page.on("console", consoleHandler);
    page.on("response", responseHandler);
    return { page, consoleHandler, responseHandler };
  });

  return {
    messages,
    stop: () => {
      for (const { page, consoleHandler, responseHandler } of handlers) {
        page.off("console", consoleHandler);
        page.off("response", responseHandler);
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
      "key_directory_checkpoint_anchor_mismatch",
      "key_directory_checkpoint_fork",
      "key_directory_pin_required",
      "initial_load_failed",
      "reconnect_failed",
      "connection_error",
      "sync gap detected",
    ].some((needle) => message.includes(needle)),
  );
}

function criticalSyncPerfEvents(entries: unknown[]): unknown[] {
  return entries.filter((entry) => {
    const event =
      typeof entry === "object" &&
      entry !== null &&
      typeof (entry as { event?: unknown }).event === "string"
        ? (entry as { event: string }).event
        : "";
    const text = stringifySyncPerfEntry(entry);
    return (
      event === "share_workspace_lineage_prewarm_failed" ||
      text.includes("key_directory_checkpoint_anchor_mismatch") ||
      text.includes("key_directory_checkpoint_fork")
    );
  });
}

function durableMutationPerfEvents(entries: unknown[]): unknown[] {
  const mutationEvents = new Set([
    "local_edit_observed",
    "update_encoded",
    "update_encrypted",
    "update_hashed",
    "update_authority_ready",
    "update_signed",
    "update_admission_built",
    "update_push_start",
    "snapshot_push_start",
  ]);
  return entries.filter((entry) => {
    if (typeof entry !== "object" || entry === null) return false;
    const event = (entry as { event?: unknown }).event;
    return typeof event === "string" && mutationEvents.has(event);
  });
}

function stringifySyncPerfEntry(entry: unknown): string {
  try {
    return JSON.stringify(entry) ?? "";
  } catch {
    return String(entry);
  }
}

async function readSyncPerf(page: Page): Promise<unknown[]> {
  return page
    .evaluate(
      () =>
        (
          window as Window & {
            __refmdE2ESyncPerf?: unknown[];
          }
        ).__refmdE2ESyncPerf?.slice(-120) ?? [],
    )
    .catch(() => []);
}

async function readPageMemorySample(
  context: BrowserContext,
  page: Page,
  documentId?: string | null,
): Promise<{
  activeDocumentStateCount: number | null;
  codemirrorCreated: number;
  codemirrorDestroyed: number;
  codemirrorRecreated: number;
  documents: number;
  jsEventListeners: number;
  jsHeapTotalMb: number;
  jsHeapUsedMb: number;
  nodes: number;
  prosemirrorCreated: number;
  prosemirrorDestroyed: number;
  prosemirrorRecreated: number;
  refCounts: number[];
  stateKeys: string[];
  syncPerfLength: number;
  url: string;
}> {
  const session = await context.newCDPSession(page);
  try {
    await session.send("Performance.enable");
    const [metrics, counters, pageDiagnostics] = await Promise.all([
      session.send("Performance.getMetrics"),
      session.send("Memory.getDOMCounters"),
      page.evaluate((id) => {
        const target = window as Window & {
          __refmdE2ESyncPerf?: Array<{ event?: unknown }>;
          __refmdGetDocumentSyncState?: (documentId: string) => {
            candidates?: Array<{ refCount?: number; stateKey?: string }>;
          } | null;
        };
        const perf = target.__refmdE2ESyncPerf ?? [];
        const count = (eventName: string) =>
          perf.filter((entry) => entry?.event === eventName).length;
        const state = id ? target.__refmdGetDocumentSyncState?.(id) : null;
        const candidates = state?.candidates ?? [];
        return {
          activeDocumentStateCount: id ? candidates.length : null,
          codemirrorCreated: count("codemirror_editor_created"),
          codemirrorDestroyed: count("codemirror_editor_destroyed"),
          codemirrorRecreated:
            count("codemirror_remote_content_reconcile_recreate") +
            count("codemirror_remote_content_reconcile_focused_recreate"),
          prosemirrorCreated: count("prosemirror_editor_created"),
          prosemirrorDestroyed: count("prosemirror_editor_destroyed"),
          prosemirrorRecreated:
            count("prosemirror_remote_content_reconcile_recreate") +
            count("prosemirror_remote_content_reconcile_focused_recreate"),
          refCounts: candidates.map((candidate) => candidate.refCount ?? -1),
          stateKeys: candidates.map((candidate) => candidate.stateKey ?? ""),
          syncPerfLength: perf.length,
        };
      }, documentId ?? null),
    ]);
    const metric = (name: string) =>
      metrics.metrics.find((item: { name: string; value: number }) => item.name === name)?.value ??
      0;
    return {
      activeDocumentStateCount: pageDiagnostics.activeDocumentStateCount,
      codemirrorCreated: pageDiagnostics.codemirrorCreated,
      codemirrorDestroyed: pageDiagnostics.codemirrorDestroyed,
      codemirrorRecreated: pageDiagnostics.codemirrorRecreated,
      documents: counters.documents,
      jsEventListeners: counters.jsEventListeners,
      jsHeapTotalMb: metric("JSHeapTotalSize") / 1024 / 1024,
      jsHeapUsedMb: metric("JSHeapUsedSize") / 1024 / 1024,
      nodes: counters.nodes,
      prosemirrorCreated: pageDiagnostics.prosemirrorCreated,
      prosemirrorDestroyed: pageDiagnostics.prosemirrorDestroyed,
      prosemirrorRecreated: pageDiagnostics.prosemirrorRecreated,
      refCounts: pageDiagnostics.refCounts,
      stateKeys: pageDiagnostics.stateKeys,
      syncPerfLength: pageDiagnostics.syncPerfLength,
      url: page.url(),
    };
  } finally {
    await session.detach().catch(() => {});
  }
}

function formatPageMemory(label: string, sample: Awaited<ReturnType<typeof readPageMemorySample>>) {
  return `${label}HeapUsedMb=${sample.jsHeapUsedMb.toFixed(1)} ${label}HeapTotalMb=${sample.jsHeapTotalMb.toFixed(
    1,
  )} ${label}Nodes=${sample.nodes} ${label}Listeners=${sample.jsEventListeners} ${label}Docs=${
    sample.documents
  } ${label}States=${sample.activeDocumentStateCount ?? "n/a"} ${label}RefCounts=${JSON.stringify(
    sample.refCounts,
  )} ${label}Cm=${sample.codemirrorCreated}/${sample.codemirrorDestroyed}/r${
    sample.codemirrorRecreated
  } ${label}Pm=${sample.prosemirrorCreated}/${sample.prosemirrorDestroyed}/r${
    sample.prosemirrorRecreated
  } ${label}Perf=${sample.syncPerfLength}`;
}

async function createEditShareLinkFromUi(page: Page, title: string): Promise<string> {
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
      throw new Error(
        `edit share link was not created: ${JSON.stringify(snapshot)}\n${String(error)}`,
      );
    });
  const link = await input.inputValue();
  await page.keyboard.press("Escape");
  return link;
}

async function waitForEditor(page: Page): Promise<void> {
  let state: "mounted" | "timeout" | `route-error:${string}` = "timeout";
  try {
    state = await page
      .waitForFunction(
        () => {
          const editorCount = document.querySelectorAll(
            '.cm-content, .ProseMirror, [role="textbox"], [contenteditable="true"], textarea',
          ).length;
          if (editorCount > 0) return "mounted";
          const bodyText = document.body.textContent ?? "";
          for (const message of [
            "Share document not found.",
            "Share not found.",
            "Invalid share document route.",
            "Invalid share link.",
            "Unable to verify shared document.",
          ]) {
            if (bodyText.includes(message)) return `route-error:${message}`;
          }
          return false;
        },
        undefined,
        { timeout: 60_000 },
      )
      .then((handle) => handle.jsonValue() as Promise<"mounted" | `route-error:${string}`>)
      .catch(() => "timeout" as const);

    if (state === "mounted") {
      await expectNoVisibleShareRouteError(page);
      return;
    }
  } catch (error) {
    const snapshot = await page
      .evaluate(() => ({
        bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 2000),
        url: window.location.href,
      }))
      .catch((snapshotError) => ({ diagnosticError: String(snapshotError) }));
    throw new Error(`editor did not mount: ${JSON.stringify(snapshot)}\n${String(error)}`);
  }

  const snapshot = await page
    .evaluate(() => ({
      bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 2000),
      cookie: document.cookie,
      syncPerf: (
        (window as Window & { __refmdE2ESyncPerf?: Array<{ event?: unknown; detail?: unknown }> })
          .__refmdE2ESyncPerf ?? []
      )
        .filter((entry) => {
          const event = typeof entry.event === "string" ? entry.event : "";
          return (
            event.startsWith("share_document_") ||
            event.startsWith("share_session_") ||
            event.startsWith("share_workspace_") ||
            event.startsWith("workspace_pin_") ||
            event === "document_sync_fail_closed"
          );
        })
        .slice(-60),
      url: window.location.href,
    }))
    .catch((snapshotError) => ({ diagnosticError: String(snapshotError) }));
  throw new Error(`editor did not mount: ${state} ${JSON.stringify(snapshot)}`);
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
          for (const message of [
            "Share document not found.",
            "Share not found.",
            "Invalid share document route.",
            "Invalid share link.",
            "Unable to verify shared document.",
          ]) {
            if (bodyText.includes(message)) return `route-error:${message}`;
          }
          return false;
        },
        undefined,
        { timeout: 60_000 },
      )
      .then(
        (handle) =>
          handle.jsonValue() as Promise<
            "mounted" | "key-ref-unavailable" | `route-error:${string}`
          >,
      )
      .catch(() => "timeout" as const);

    if (state === "mounted") {
      await expect(page).toHaveURL(SHARE_DOCUMENT_ROUTE_RE, {
        timeout: 60_000,
      });
      await expectNoVisibleShareRouteError(page);
      return;
    }
    if (state === "key-ref-unavailable" && attempt === 0) {
      await page.goto(fullShareLink, { waitUntil: "domcontentloaded" });
      await expect(page).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
        timeout: 60_000,
      });
      continue;
    }

    const snapshot = await page
      .evaluate(() => ({
        bodyText: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 2000),
        url: window.location.href,
      }))
      .catch((snapshotError) => ({ diagnosticError: String(snapshotError) }));
    throw new Error(`share editor did not mount: ${state} ${JSON.stringify(snapshot)}`);
  }
}

async function expectNoVisibleShareRouteError(page: Page): Promise<void> {
  const bodyText = await page.locator("body").innerText({ timeout: 10_000 });
  for (const message of SHARE_ROUTE_ERROR_TEXTS) {
    expect(bodyText).not.toContain(message);
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

async function ensureSplitEditor(page: Page): Promise<void> {
  const cmVisible = await page
    .locator(".cm-content")
    .isVisible()
    .catch(() => false);
  const pmVisible = await page
    .locator('[data-testid="markdown-preview"]')
    .isVisible()
    .catch(() => false);
  if (cmVisible && pmVisible) return;

  const trigger = page
    .locator(
      ".mosaic-window-toolbar [data-slot='dropdown-menu-trigger'], .mosaic-window-toolbar button",
    )
    .last();
  await trigger.waitFor({ state: "visible", timeout: 10_000 });
  await trigger.click();
  await page.waitForTimeout(E2E_DELAYS.poll);

  const menuContent = page.locator('[data-slot="dropdown-menu-content"]');
  await menuContent.waitFor({ state: "visible", timeout: 5_000 });
  await menuContent
    .locator('[data-slot="dropdown-menu-item"]', { hasText: "Switch to Split" })
    .click();
  await page.waitForTimeout(E2E_DELAYS.routeSettle);

  await expect(page.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('[data-testid="markdown-preview"]')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator(".cm-content")).toHaveAttribute("contenteditable", "true");
  await expect(page.locator(".ProseMirror")).not.toBeVisible({ timeout: 5_000 });
}

async function switchToWysiwygOnly(page: Page): Promise<void> {
  const cmVisible = await page
    .locator(".cm-content")
    .isVisible()
    .catch(() => false);
  const pmVisible = await page
    .locator('.ProseMirror, [data-testid="markdown-preview"]')
    .isVisible()
    .catch(() => false);
  const pmEditable = await page
    .locator('.ProseMirror[contenteditable="true"]')
    .isVisible()
    .catch(() => false);
  if (!cmVisible && pmVisible && pmEditable) return;

  const trigger = page
    .locator(
      ".mosaic-window-toolbar [data-slot='dropdown-menu-trigger'], .mosaic-window-toolbar button",
    )
    .last();
  await trigger.waitFor({ state: "visible", timeout: 10_000 });
  await trigger.click();
  await page.waitForTimeout(E2E_DELAYS.poll);

  const menuContent = page.locator('[data-slot="dropdown-menu-content"]');
  await menuContent.waitFor({ state: "visible", timeout: 5_000 });
  const itemName = cmVisible && pmVisible ? "WYSIWYG only" : "Switch to WYSIWYG";
  await menuContent.getByRole("menuitem", { name: itemName }).click();
  await page.waitForTimeout(E2E_DELAYS.routeSettle);

  await expect(page.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('.ProseMirror[contenteditable="true"]')).toBeVisible({
    timeout: 10_000,
  });
  await expect(page.locator(".cm-content")).not.toBeVisible({ timeout: 5_000 });
}

async function typeByUserClickAndKeyboard(page: Page, text: string): Promise<void> {
  await page.bringToFront();
  await waitForDocumentWriteSessionReady(page, { allowGenesisSnapshot: true });
  await typeByUserClickAndKeyboardWithoutWriteSessionWait(page, text);
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

async function typeByUserClickAndKeyboardWithoutWriteSessionWait(
  page: Page,
  text: string,
): Promise<void> {
  await page.bringToFront();
  await typeBySpecificEditorClickAndKeyboard(
    page,
    page.locator('.cm-content[contenteditable="true"]').first(),
    text,
    "codemirror",
  );
}

async function replaceMarkdownEditorTextByKeyboard(page: Page, text: string): Promise<void> {
  await page.bringToFront();
  await waitForDocumentWriteSessionReady(page, { allowGenesisSnapshot: true });
  const editor = page.locator('.cm-content[contenteditable="true"]').first();
  await focusSpecificEditorAtEnd(page, editor, "markdown replacement editor", {
    appendNewline: false,
  });
  await page.keyboard.press("Control+A");
  await page.keyboard.insertText(text);
  await expectVisibleMarkdownEditorTextEquals(page, text, 5_000);
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

async function appendMarkdownParagraphsByKeyboard(page: Page, paragraphs: string[]): Promise<void> {
  for (const paragraph of paragraphs) {
    await page.keyboard.press("Enter");
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(paragraph);
    await page.waitForTimeout(E2E_DELAYS.inputPropagation);
  }
}

async function appendProseMirrorParagraphsByKeyboard(
  page: Page,
  paragraphs: string[],
): Promise<void> {
  await focusProseMirrorEditorAtDocumentEnd(page);
  for (const paragraph of paragraphs) {
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(paragraph);
    await page.waitForTimeout(E2E_DELAYS.inputPropagation);
  }
}

async function focusProseMirrorEditorAtDocumentEnd(page: Page): Promise<void> {
  const editor = page.locator('.ProseMirror[contenteditable="true"]').first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  const point = await editor.evaluate((root) => {
    root.scrollIntoView({ block: "end" });
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let lastText: Text | null = null;
    while (walker.nextNode()) {
      const node = walker.currentNode as Text;
      if ((node.textContent ?? "").length > 0) lastText = node;
    }

    const range = document.createRange();
    if (lastText) {
      range.setStart(lastText, lastText.length);
      range.collapse(true);
    } else {
      range.selectNodeContents(root);
      range.collapse(false);
    }

    const rect = [...range.getClientRects()].at(-1) ?? root.getBoundingClientRect();
    const rootRect = root.getBoundingClientRect();
    return {
      x: Math.min(Math.max(rect.right + 2, rootRect.left + 4), rootRect.right - 4),
      y: Math.min(Math.max(rect.top + rect.height / 2, rootRect.top + 4), rootRect.bottom - 4),
    };
  });
  await page.mouse.click(point.x, point.y);
  await expect
    .poll(
      async () =>
        editor.evaluate((element) => {
          const active = document.activeElement;
          return active === element || element.contains(active);
        }),
      {
        timeout: 5_000,
        message: "prosemirror paragraph append editor did not receive focus from a real click",
      },
    )
    .toBe(true);
}

async function expectNoContentPreviewOverlay(page: Page): Promise<void> {
  await expect(page.locator('[data-refmd-content-preview="true"]')).toHaveCount(0, {
    timeout: 5_000,
  });
}

async function clickVisibleMarkdownLineEnd(page: Page, exactLineText: string): Promise<void> {
  const point = await page
    .locator('.cm-content[contenteditable="true"]')
    .first()
    .evaluate((editor, expectedText) => {
      const remoteCursorLabelRe =
        /\u2060+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\u2060*/gi;
      const element = [...editor.querySelectorAll<HTMLElement>(".cm-line")].find(
        (candidate) =>
          (candidate.textContent || "").replace(remoteCursorLabelRe, "") === expectedText,
      );
      if (!element) {
        throw new Error(`markdown line ${expectedText} was not visible`);
      }
      const range = document.createRange();
      range.selectNodeContents(element);
      range.collapse(false);
      const rects = [...range.getClientRects()];
      const textEnd = rects.at(-1);
      const lineRect = element.getBoundingClientRect();
      return {
        x: (textEnd?.right ?? lineRect.left + 4) + 2,
        y: lineRect.top + lineRect.height / 2,
      };
    }, exactLineText);
  await page.mouse.click(point.x, point.y);
  await expect
    .poll(
      async () =>
        page
          .locator('.cm-content[contenteditable="true"]')
          .first()
          .evaluate((editor) => {
            const active = document.activeElement;
            return active === editor || !!editor?.contains(active);
          }),
      {
        timeout: 5_000,
        message: `markdown line ${exactLineText} did not focus from a real click`,
      },
    )
    .toBe(true);
  await page.keyboard.press("End");
}

async function typeBySpecificEditorClickAndKeyboard(
  page: Page,
  editor: Locator,
  text: string,
  label: string,
): Promise<void> {
  await focusSpecificEditorAtEnd(page, editor, label);
  await typeFocusedEditorText(page, editor, text, label, 1);
}

async function focusSpecificEditorAtEnd(
  page: Page,
  editor: Locator,
  label: string,
  options: { appendNewline?: boolean } = {},
): Promise<void> {
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click();
  await expect
    .poll(
      async () =>
        editor.evaluate((element) => {
          const active = document.activeElement;
          return active === element || element.contains(active);
        }),
      {
        timeout: 5_000,
        message: `${label} editor did not receive focus from a real click`,
      },
    )
    .toBe(true);
  await expect(page.locator('[data-refmd-content-preview="true"]')).toHaveCount(0, {
    timeout: 5_000,
  });
  await page.keyboard.press("Control+End");
  if (options.appendNewline !== false) {
    await page.keyboard.press("Enter");
  }
}

async function typeFocusedEditorText(
  page: Page,
  editor: Locator,
  text: string,
  label: string,
  delay: number,
): Promise<void> {
  const beforeText = await readEditorText(page);
  await editor.pressSequentially(text, { delay });
  if (
    await expectEditorTextContains(page, text, REALTIME_TEXT_LATENCY_MS)
      .then(() => true)
      .catch(() => false)
  ) {
    return;
  }
  throw new Error(
    `${label} real editor click + keyboard input did not mutate content: ${JSON.stringify({
      ...(await editorFocusDiagnostics(page, "input-did-not-mutate")),
      afterText: await readEditorText(page),
      beforeText,
    })}`,
  );
}

async function insertFocusedEditorText(
  page: Page,
  editor: Locator,
  insertedText: string,
  expectedText: string,
  label: string,
): Promise<void> {
  const beforeText = await readEditorText(page);
  await page.keyboard.insertText(insertedText);
  if (
    await expectEditorTextContains(page, expectedText, REALTIME_TEXT_LATENCY_MS)
      .then(() => true)
      .catch(() => false)
  ) {
    return;
  }
  throw new Error(
    `${label} real editor click + keyboard insertText did not mutate content: ${JSON.stringify({
      ...(await editorFocusDiagnostics(page, "insert-text-did-not-mutate")),
      afterText: await readEditorText(page),
      beforeText,
      editorVisible: await editor.isVisible().catch(() => false),
    })}`,
  );
}

async function insertFocusedEditorTextAndStartLatencyClock(
  page: Page,
  editor: Locator,
  insertedText: string,
  expectedText: string,
  label: string,
): Promise<{ insertedAt: number; localMutation: Promise<void> }> {
  const beforeText = await readEditorText(page);
  await page.keyboard.insertText(insertedText);
  const insertedAt = Date.now();
  const localMutation = expectEditorTextContains(
    page,
    expectedText,
    REALTIME_TEXT_LATENCY_MS,
  ).catch(async () => {
    throw new Error(
      `${label} real editor click + keyboard insertText did not mutate content: ${JSON.stringify({
        ...(await editorFocusDiagnostics(page, "insert-text-did-not-mutate")),
        afterText: await readEditorText(page),
        beforeText,
        editorVisible: await editor.isVisible().catch(() => false),
      })}`,
    );
  });
  return { insertedAt, localMutation };
}

async function focusAnyRealEditorAtEnd(
  page: Page,
  label: string,
  options: { appendNewline?: boolean } = {},
): Promise<{ editor: Locator; label: string }> {
  await page.bringToFront();
  const candidates: Array<{ editor: Locator; label: string }> = [
    {
      editor: page.locator('.cm-content[contenteditable="true"]').first(),
      label: `${label} codemirror`,
    },
    {
      editor: page.locator('.ProseMirror[contenteditable="true"]').first(),
      label: `${label} prosemirror`,
    },
    {
      editor: page.locator('[role="textbox"][contenteditable="true"], textarea').first(),
      label: `${label} textbox`,
    },
  ];
  const failures: unknown[] = [];

  for (const candidate of candidates) {
    if (!(await candidate.editor.isVisible({ timeout: 2_000 }).catch(() => false))) continue;
    try {
      await focusSpecificEditorAtEnd(page, candidate.editor, candidate.label, options);
      return candidate;
    } catch (error) {
      failures.push({
        label: candidate.label,
        error: String(error),
      });
    }
  }

  throw new Error(
    `${label} could not focus any real editable surface: ${JSON.stringify({
      failures,
      diagnostics: await editorFocusDiagnostics(page, "no-real-editor-focus-succeeded"),
    })}`,
  );
}

async function typeByAnyRealEditorClickAndKeyboard(
  page: Page,
  text: string,
  label: string,
): Promise<void> {
  await page.bringToFront();
  const candidates: Array<{ editor: Locator; label: string }> = [
    {
      editor: page.locator('.cm-content[contenteditable="true"]').first(),
      label: `${label} codemirror`,
    },
    {
      editor: page.locator('.ProseMirror[contenteditable="true"]').first(),
      label: `${label} prosemirror`,
    },
    {
      editor: page.locator('[role="textbox"][contenteditable="true"], textarea').first(),
      label: `${label} textbox`,
    },
  ];
  const failures: unknown[] = [];

  for (const candidate of candidates) {
    if (!(await candidate.editor.isVisible({ timeout: 2_000 }).catch(() => false))) continue;
    try {
      await typeBySpecificEditorClickAndKeyboard(page, candidate.editor, text, candidate.label);
      return;
    } catch (error) {
      failures.push({
        label: candidate.label,
        error: String(error),
      });
    }
  }

  throw new Error(
    `${label} could not type through any real editable surface: ${JSON.stringify({
      failures,
      diagnostics: await editorFocusDiagnostics(page, "no-real-editor-input-succeeded"),
    })}`,
  );
}

async function editorFocusDiagnostics(page: Page, reason: string): Promise<unknown> {
  return page.evaluate((diagnosticReason) => {
    const active = document.activeElement;
    const describe = (element: Element | null) =>
      element instanceof HTMLElement
        ? {
            className: element.className,
            contentEditable: element.getAttribute("contenteditable"),
            focused: element === active || element.contains(active),
            tag: element.tagName,
            text: (element.innerText || element.textContent || "").slice(0, 200),
          }
        : null;
    return {
      activeElement: describe(active),
      cmEditors: [...document.querySelectorAll(".cm-editor")].map(describe),
      editableSurfaces: [
        ...document.querySelectorAll(
          '.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"]',
        ),
      ].map(describe),
      overlays: [...document.querySelectorAll('[data-refmd-content-preview="true"]')].map(describe),
      reason: diagnosticReason,
      selection: window.getSelection()?.toString() ?? "",
      state: (() => {
        const documentId = window.location.pathname.split("/").pop() ?? "";
        return window.__refmdGetDocumentSyncState?.(documentId) ?? null;
      })(),
    };
  }, reason);
}

async function typeByEditorSurfaceClickAndKeyboard(page: Page, text: string): Promise<void> {
  await page.bringToFront();
  await waitForDocumentWriteSessionReady(page);
  const surface = page.locator('[data-testid="document-editor"]').first();
  await expect(surface).toBeVisible({ timeout: 30_000 });
  const box = await surface.boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.click(box!.x + box!.width / 2, box!.y + box!.height * 0.75);
  const editable = page
    .locator('.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"]')
    .first();
  await expect
    .poll(
      async () =>
        editable.evaluate((element) => {
          const active = document.activeElement;
          return active === element || element.contains(active);
        }),
      {
        timeout: 5_000,
        message: "editor surface click did not focus an editable editor",
      },
    )
    .toBe(true);
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText(text);
  await expectEditorTextContains(page, text, 15_000);
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

async function typeByProseMirrorSurfaceClickAndKeyboard(page: Page, text: string): Promise<void> {
  await page.bringToFront();
  await waitForDocumentWriteSessionReady(page);
  const surface = page.locator('.ProseMirror[contenteditable="true"]').first();
  await expect(surface).toBeVisible({ timeout: 30_000 });
  const box = await surface.boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.click(box!.x + box!.width / 2, box!.y + box!.height * 0.75);
  await expect
    .poll(
      async () =>
        surface.evaluate((element) => {
          const active = document.activeElement;
          return active === element || element.contains(active);
        }),
      {
        timeout: 5_000,
        message: "ProseMirror surface click did not focus the editor",
      },
    )
    .toBe(true);
  await expect(page.locator('[data-refmd-content-preview="true"]')).toHaveCount(0, {
    timeout: 5_000,
  });
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await surface.pressSequentially(text, { delay: 10 });
  await expectEditorTextContains(page, text, 15_000);
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

async function expectNoDocumentSecurityFailure(page: Page): Promise<void> {
  await expect
    .poll(
      async () =>
        page
          .locator("body")
          .innerText()
          .catch(() => ""),
      {
        timeout: 5_000,
        message: "document security failure was visible",
      },
    )
    .not.toMatch(/verification_failed|State Inconsistency|Clock rollback/i);
}

async function observeDocumentSecurityFailures(page: Page, documentId?: string): Promise<void> {
  await page.evaluate((id) => {
    const win = window as Window & {
      __refmdE2ESecurityFailures?: unknown[];
      __refmdE2ESecurityFailureObserver?: MutationObserver;
      __refmdGetDocumentSyncState?: (documentId: string) => unknown;
      __refmdE2ESyncPerf?: unknown[];
    };
    win.__refmdE2ESecurityFailures = [];
    win.__refmdE2ESecurityFailureObserver?.disconnect();
    const scan = () => {
      const text = document.body?.innerText ?? "";
      if (/verification_failed|State Inconsistency|Clock rollback/i.test(text)) {
        win.__refmdE2ESecurityFailures?.push({
          text: text.replace(/\s+/g, " ").trim().slice(0, 2000),
          state: id ? win.__refmdGetDocumentSyncState?.(id) : null,
          syncPerf: win.__refmdE2ESyncPerf?.slice(-60) ?? [],
        });
      }
    };
    const observer = new MutationObserver(scan);
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    win.__refmdE2ESecurityFailureObserver = observer;
    scan();
  }, documentId);
}

async function expectNoObservedDocumentSecurityFailure(page: Page): Promise<void> {
  const failures = await page.evaluate(
    () =>
      (
        window as Window & {
          __refmdE2ESecurityFailures?: unknown[];
        }
      ).__refmdE2ESecurityFailures ?? [],
  );
  expect(failures).toEqual([]);
}

async function waitForContentVisible(
  page: Page,
  snippet: string,
  startedAt: number,
): Promise<{ stateTextMs: number; domTextMs: number }> {
  const stateText = expect
    .poll(
      async () => {
        const documentId = currentDocumentId(page);
        const text = await page
          .evaluate((id) => window.__refmdGetDocumentText?.(id) ?? "", documentId)
          .catch(() => "");
        return text.includes(snippet);
      },
      {
        timeout: 60_000,
        message: `shared document state did not contain content: ${snippet}`,
      },
    )
    .toBe(true)
    .then(() => Date.now() - startedAt);

  const domText = expect
    .poll(async () => (await readEditorText(page)).includes(snippet), {
      timeout: 60_000,
      message: `shared document content did not become visible: ${snippet}`,
    })
    .toBe(true)
    .then(() => Date.now() - startedAt);

  const [stateTextMs, domTextMs] = await Promise.all([stateText, domText]);
  return { stateTextMs, domTextMs };
}

async function waitForWritableEditorSurface(page: Page): Promise<void> {
  await waitForDocumentWriteSessionReady(page);
  await waitForEditableEditorSurface(page);
}

async function waitForEditableEditorSurface(page: Page): Promise<void> {
  await expect(
    page
      .locator('.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"]')
      .first(),
  ).toBeVisible({ timeout: 30_000 });
}

async function typeInVisibleEditor(page: Page, text: string): Promise<void> {
  await page.bringToFront();
  await waitForDocumentWriteSessionReady(page, { allowGenesisSnapshot: true });
  await typeByAnyRealEditorClickAndKeyboard(page, text, "visible editor");
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

async function typeLineBurst(page: Page, prefix: string, count: number): Promise<void> {
  await waitForDocumentWriteSessionReady(page, { allowGenesisSnapshot: true });
  await page.bringToFront();
  if (count <= 0) return;

  await typeByAnyRealEditorClickAndKeyboard(page, `${prefix}-0`, "burst editor");
  for (let i = 1; i < count; i += 1) {
    await page.keyboard.press("Enter");
    await page.keyboard.insertText(`${prefix}-${i}`);
    await page.waitForTimeout(E2E_DELAYS.inputPropagation);
  }
  await expectEditorTextContains(page, `${prefix}-${count - 1}`, 30_000);
  await flushDocumentSync(page);
  await waitForDocumentSyncReady(page);
}

test("anonymous edit share renders content within visible workspace after first open", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;
  let ownerBeforeCloseState: unknown = null;
  let ownerBeforeCloseSyncPerf: unknown[] = [];

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Existing Content");
    await openDocument(ownerPage, "Anonymous Share Existing Content");
    await typeInVisibleEditor(ownerPage, "existing-content-before-share-open");

    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Existing Content",
    );
    ownerBeforeCloseState = await ownerPage
      .evaluate(
        (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
        currentDocumentId(ownerPage),
      )
      .catch((err) => ({ diagnosticError: String(err) }));
    ownerBeforeCloseSyncPerf = await readSyncPerf(ownerPage);
    await ownerContext.close();
    ownerContext = undefined;

    const startedAt = Date.now();
    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await expect(guestPage).toHaveURL(SHARE_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    const routedMs = Date.now() - startedAt;
    const contentVisible = await waitForContentVisible(
      guestPage,
      "existing-content-before-share-open",
      startedAt,
    );
    const syncPerf = await readSyncPerf(guestPage);
    const rootReadyEvent = syncPerf.find(
      (event) => event.event === "share_document_workspace_root_ready",
    );
    const contentReadyEvent = syncPerf.find(
      (event) => event.event === "share_document_workspace_content_ready",
    );
    expect(rootReadyEvent?.at).toEqual(expect.any(Number));
    expect(contentReadyEvent?.at).toEqual(expect.any(Number));
    const navigationToDomMs = contentVisible.domTextMs;
    const visibleWorkspaceContentMs =
      contentVisible.domTextMs - ((rootReadyEvent!.at as number) - startedAt);
    const rootAfterContentReadyMs =
      (rootReadyEvent!.at as number) - (contentReadyEvent!.at as number);
    console.log(
      `[share-visible-content-open] routedMs=${routedMs} stateTextMs=${
        contentVisible.stateTextMs
      } navigationToDomMs=${navigationToDomMs} visibleWorkspaceContentMs=${visibleWorkspaceContentMs} rootAfterContentReadyMs=${rootAfterContentReadyMs} syncPerf=${JSON.stringify(
        syncPerf,
      )}`,
    );
    await testInfo.attach("share-visible-content-open", {
      body: JSON.stringify(
        {
          routedMs,
          contentVisible,
          navigationToDomMs,
          visibleWorkspaceContentMs,
          rootAfterContentReadyMs,
          syncPerf,
        },
        null,
        2,
      ),
      contentType: "application/json",
    });
    // The SLA starts when the Share workspace is made visible. Navigation-to-DOM
    // still includes design-required anonymous bootstrap and verification work.
    expect(visibleWorkspaceContentMs).toBeGreaterThanOrEqual(0);
    expect(visibleWorkspaceContentMs).toBeLessThan(1000);
    expect(rootAfterContentReadyMs).toBeGreaterThanOrEqual(0);

    await waitForDocumentSyncReady(guestPage);
    await expectNoDocumentSecurityFailure(guestPage);
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    expect(criticalSyncPerfEvents(await readSyncPerf(guestPage))).toEqual([]);
  } catch (error) {
    if (diagnostics) {
      const ownerPage = ownerContext?.pages()[0];
      const guestPage = guestContext?.pages()[0];
      const ownerDocumentId = ownerPage ? currentDocumentIdOrNull(ownerPage) : null;
      const guestDocumentId = guestPage ? currentDocumentIdOrNull(guestPage) : null;
      const ownerState =
        ownerPage && ownerDocumentId
          ? await ownerPage
              .evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, ownerDocumentId)
              .catch((err) => ({ diagnosticError: String(err) }))
          : null;
      const guestState =
        guestPage && guestDocumentId
          ? await guestPage
              .evaluate((id) => window.__refmdGetDocumentSyncState?.(id) ?? null, guestDocumentId)
              .catch((err) => ({ diagnosticError: String(err) }))
          : null;
      const ownerSyncPerf = ownerPage ? await readSyncPerf(ownerPage) : [];
      const guestSyncPerf = guestPage ? await readSyncPerf(guestPage) : [];
      await testInfo.attach("sync-diagnostics", {
        body: [
          "sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-before-close-state: ${JSON.stringify(ownerBeforeCloseState)}`,
          `owner-before-close-sync-perf: ${JSON.stringify(ownerBeforeCloseSyncPerf)}`,
          `owner-state: ${JSON.stringify(ownerState)}`,
          `guest-state: ${JSON.stringify(guestState)}`,
          `owner-sync-perf: ${JSON.stringify(ownerSyncPerf)}`,
          `guest-sync-perf: ${JSON.stringify(guestSyncPerf)}`,
        ].join("\n"),
        contentType: "text/plain",
      });
    }
    throw error;
  } finally {
    diagnostics?.stop();
    await ownerContext?.close().catch(() => {});
    await guestContext?.close().catch(() => {});
  }
});

test("anonymous edit share editor accepts real click focus and keyboard input", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Real Keyboard Edit");
    await openDocument(ownerPage, "Anonymous Share Real Keyboard Edit");
    await typeInVisibleEditor(ownerPage, "owner-content-before-real-keyboard");
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Real Keyboard Edit",
    );

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await expectEditorTextContains(guestPage, "owner-content-before-real-keyboard", 60_000);
    const contentVisibleAt = Date.now();
    await waitForShareEditor(guestPage, shareLink);
    await waitForEditableEditorSurface(guestPage);
    const visibleContentToEditableMs = Date.now() - contentVisibleAt;
    expect(visibleContentToEditableMs).toBeLessThanOrEqual(1_000);
    console.log(`[share-editable-after-content] elapsedMs=${visibleContentToEditableMs}`);
    await typeByUserClickAndKeyboardWithoutWriteSessionWait(guestPage, "guest-cm-keyboard-edit");
    await flushDocumentSync(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectEditorTextContains(ownerPage, "guest-cm-keyboard-edit", 60_000);

    await typeByUserClickAndKeyboard(ownerPage, "owner-real-keyboard-after-guest-edit");
    await expectEditorTextContains(guestPage, "owner-real-keyboard-after-guest-edit", 60_000);

    await typeByEditorSurfaceClickAndKeyboard(guestPage, "guest-surface-keyboard-edit");
    await expectEditorTextContains(ownerPage, "guest-surface-keyboard-edit", 60_000);

    await switchToWysiwygOnly(guestPage);
    await typeByProseMirrorSurfaceClickAndKeyboard(guestPage, "guest-wysiwyg-keyboard-edit");
    await expectEditorTextContains(ownerPage, "guest-wysiwyg-keyboard-edit", 60_000);

    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            activeElement:
              document.activeElement instanceof HTMLElement
                ? {
                    tag: document.activeElement.tagName,
                    className: document.activeElement.className,
                    text: document.activeElement.textContent?.slice(0, 200),
                  }
                : null,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            activeElement:
              document.activeElement instanceof HTMLElement
                ? {
                    tag: document.activeElement.tagName,
                    className: document.activeElement.className,
                    text: document.activeElement.textContent?.slice(0, 200),
                  }
                : null,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      await testInfo.attach("sync-diagnostics", {
        body: [
          "sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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

test("anonymous edit share remains editable after a DEK deadline rotation", async ({ browser }) => {
  const deadlineSeconds = Number(process.env.REFMD_DEK_ROTATION_SECONDS ?? "0");
  test.skip(
    !Number.isInteger(deadlineSeconds) || deadlineSeconds < 5 || deadlineSeconds > 60,
    "run with REFMD_DEK_ROTATION_SECONDS between 5 and 60",
  );
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const title = `Share Deadline Rotation ${Date.now()}`;
  const ownerContext = await newStrictShareContext(browser, { acceptDownloads: true });
  const guestContext = await newStrictShareContext(browser, { acceptDownloads: true });

  try {
    await ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      const logs: unknown[] = [];
      (window as Window & { __refmdRotationLogs?: unknown[] }).__refmdRotationLogs = logs;
      window.addEventListener("refmd:client-log", (event) => {
        logs.push((event as CustomEvent).detail);
      });
    });
    await guestContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
      const logs: unknown[] = [];
      (window as Window & { __refmdRotationLogs?: unknown[] }).__refmdRotationLogs = logs;
      window.addEventListener("refmd:client-log", (event) => {
        logs.push((event as CustomEvent).detail);
      });
    });

    const ownerPage = await ownerContext.newPage();
    let guestPage = await guestContext.newPage();

    await registerAccount(ownerPage);
    await createDocument(ownerPage, title);
    await openDocument(ownerPage, title);
    await typeInVisibleEditor(ownerPage, "owner-before-share-deadline");
    const shareLink = await createEditShareLinkFromUi(ownerPage, title);

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await waitForShareEditor(guestPage, shareLink);
    await expectEditorTextContains(guestPage, "owner-before-share-deadline", 60_000);

    await ownerPage.waitForTimeout((deadlineSeconds + 1) * 1_000);
    await ownerPage.reload({ waitUntil: "domcontentloaded" });
    await waitForEditor(ownerPage);

    const ownerDocumentId = currentDocumentId(ownerPage);
    await expect
      .poll(
        () =>
          ownerPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.keyVersion ?? 0,
            ownerDocumentId,
          ),
        { timeout: 90_000, message: "owner did not complete the deadline DEK rotation" },
      )
      .toBeGreaterThanOrEqual(2)
      .catch(async (error) => {
        const snapshot = await ownerPage.evaluate(
          (id) => ({
            body: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200),
            logs: (window as Window & { __refmdRotationLogs?: unknown[] }).__refmdRotationLogs,
            perf: (window as Window & { __refmdE2ESyncPerf?: unknown[] }).__refmdE2ESyncPerf,
            state: window.__refmdGetDocumentSyncState?.(id) ?? null,
            url: window.location.href,
          }),
          ownerDocumentId,
        );
        throw new Error(`${String(error)}\nrotation-diagnostics=${JSON.stringify(snapshot)}`);
      });
    await waitForDocumentSyncReady(ownerPage);
    await typeInVisibleEditor(ownerPage, "owner-after-share-deadline");
    await flushDocumentSync(ownerPage);
    await waitForDocumentSyncReady(ownerPage);
    await expectEditorTextContains(guestPage, "owner-after-share-deadline", 60_000).catch(
      async (error) => {
        const [ownerSnapshot, guestSnapshot] = await Promise.all(
          [ownerPage, guestPage].map(async (page) => {
            const id = currentDocumentId(page);
            return page.evaluate(
              (documentId) => ({
                body: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200),
                logs: (window as Window & { __refmdRotationLogs?: unknown[] }).__refmdRotationLogs,
                perf: (window as Window & { __refmdE2ESyncPerf?: unknown[] }).__refmdE2ESyncPerf,
                state: window.__refmdGetDocumentSyncState?.(documentId) ?? null,
                url: window.location.href,
              }),
              id,
            );
          }),
        );
        throw new Error(
          `${String(error)}\nlive-rotation-diagnostics=${JSON.stringify({ ownerSnapshot, guestSnapshot })}`,
        );
      },
    );

    const liveGuestDocumentId = currentDocumentId(guestPage);
    await expect
      .poll(
        () =>
          guestPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.keyVersion ?? 0,
            liveGuestDocumentId,
          ),
        { timeout: 60_000, message: "live share participant did not receive the rotated DEK" },
      )
      .toBeGreaterThanOrEqual(2);
    await typeByUserClickAndKeyboardWithoutWriteSessionWait(
      guestPage,
      "guest-live-after-share-deadline",
    );
    await flushDocumentSync(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectEditorTextContains(ownerPage, "guest-live-after-share-deadline", 60_000);

    const ownerDocumentUrl = ownerPage.url();
    await guestPage.close();
    await ownerPage.close();

    guestPage = await guestContext.newPage();
    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await waitForShareEditor(guestPage, shareLink).catch(async (error) => {
      const snapshot = await guestPage.evaluate(() => {
        const perf =
          (window as Window & { __refmdE2ESyncPerf?: Array<Record<string, unknown>> })
            .__refmdE2ESyncPerf ?? [];
        const documentId = perf.findLast((entry) => {
          const detail = entry.detail as Record<string, unknown> | undefined;
          return typeof detail?.documentId === "string";
        })?.detail as Record<string, unknown> | undefined;
        const resolvedDocumentId =
          typeof documentId?.documentId === "string" ? documentId.documentId : null;
        return {
          body: document.body.textContent?.replace(/\s+/g, " ").trim().slice(0, 1200),
          logs: (window as Window & { __refmdRotationLogs?: unknown[] }).__refmdRotationLogs,
          perf,
          state: resolvedDocumentId
            ? window.__refmdGetDocumentSyncState?.(resolvedDocumentId)
            : null,
          url: window.location.href,
        };
      });
      throw new Error(`${String(error)}\nguest-rotation-diagnostics=${JSON.stringify(snapshot)}`);
    });
    await expectEditorTextContains(guestPage, "owner-after-share-deadline", 60_000);
    await expectEditorTextContains(guestPage, "guest-live-after-share-deadline", 60_000);

    const guestDocumentId = currentDocumentId(guestPage);
    await expect
      .poll(
        () =>
          guestPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id)?.keyVersion ?? 0,
            guestDocumentId,
          ),
        { timeout: 60_000, message: "share participant did not bootstrap the rotated DEK" },
      )
      .toBeGreaterThanOrEqual(2);

    await typeByUserClickAndKeyboardWithoutWriteSessionWait(
      guestPage,
      "guest-reentry-after-share-deadline",
    );
    await flushDocumentSync(guestPage);
    await waitForDocumentSyncReady(guestPage);

    const reopenedOwnerPage = await ownerContext.newPage();
    await reopenedOwnerPage.goto(ownerDocumentUrl, { waitUntil: "domcontentloaded" });
    await waitForEditor(reopenedOwnerPage);
    await expectEditorTextContains(reopenedOwnerPage, "guest-reentry-after-share-deadline", 60_000);
    await expectNoDocumentSecurityFailure(reopenedOwnerPage);
    await expectNoDocumentSecurityFailure(guestPage);
  } finally {
    await guestContext.close().catch(() => {});
    await ownerContext.close().catch(() => {});
  }
});

test("diagnostic: anonymous edit share can remain open idle without sync or route errors", async ({
  browser,
}) => {
  test.skip(
    process.env.REFMD_E2E_CPU_OPEN_IDLE !== "1",
    "diagnostic workload for external BEAM CPU sampling",
  );
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const idleMs = Number.parseInt(process.env.REFMD_E2E_CPU_OPEN_IDLE_MS ?? "45000", 10);
  const sampleEveryMs = Number.parseInt(process.env.REFMD_E2E_MEMORY_SAMPLE_EVERY_MS ?? "5000", 10);
  const editRounds = Number.parseInt(process.env.REFMD_E2E_MEMORY_EDIT_ROUNDS ?? "0", 10);
  const reloadRounds = Number.parseInt(process.env.REFMD_E2E_MEMORY_RELOAD_ROUNDS ?? "0", 10);
  const maxHeapTotalMb = Number.parseInt(
    process.env.REFMD_E2E_MEMORY_MAX_HEAP_TOTAL_MB ?? "256",
    10,
  );
  const maxDocumentsAfterIdle = Number.parseInt(
    process.env.REFMD_E2E_MEMORY_MAX_DOCUMENTS_AFTER_IDLE ?? "2",
    10,
  );
  const ownerContext = await newStrictShareContext(browser, {
    acceptDownloads: true,
  });
  const guestContext = await newStrictShareContext(browser, {
    acceptDownloads: true,
  });
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    await ownerContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    await guestContext.addInitScript(() => {
      window.__REFMD_E2E__ = true;
    });
    const ownerPage = await ownerContext.newPage();
    const guestPage = await guestContext.newPage();
    const activeDiagnostics = collectSyncDiagnostics([ownerPage, guestPage]);
    diagnostics = activeDiagnostics;

    await registerAccount(ownerPage);
    await createDocument(ownerPage, "Anonymous Share CPU Idle");
    await openDocument(ownerPage, "Anonymous Share CPU Idle");
    await typeInVisibleEditor(ownerPage, "owner-content-before-idle");
    const shareLink = await createEditShareLinkFromUi(ownerPage, "Anonymous Share CPU Idle");

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await expectEditorTextContains(guestPage, "owner-content-before-idle", 60_000);
    await waitForShareEditor(guestPage, shareLink);
    await waitForEditableEditorSurface(guestPage);
    await waitForDocumentSyncReady(ownerPage);
    await waitForDocumentSyncReady(guestPage);
    const ownerDocumentId = currentDocumentId(ownerPage);
    const guestDocumentId = ownerDocumentId;
    const memorySamples: Array<{
      guest: Awaited<ReturnType<typeof readPageMemorySample>>;
      label: string;
      owner: Awaited<ReturnType<typeof readPageMemorySample>>;
      sampleIndex: number;
    }> = [];

    const logMemorySample = async (label: string, sampleIndex: number) => {
      const ownerMemory = await readPageMemorySample(ownerContext, ownerPage, ownerDocumentId);
      const guestMemory = await readPageMemorySample(guestContext, guestPage, guestDocumentId);
      memorySamples.push({
        guest: guestMemory,
        label,
        owner: ownerMemory,
        sampleIndex,
      });
      console.log(
        `[share-open-memory] label=${label} sample=${sampleIndex} ${formatPageMemory(
          "owner",
          ownerMemory,
        )} ${formatPageMemory("guest", guestMemory)}`,
      );
    };

    await logMemorySample("ready", 0);

    for (let round = 0; round < editRounds; round += 1) {
      const ownerText = `owner-memory-round-${round}`;
      await typeInVisibleEditor(ownerPage, `\n${ownerText}`);
      await expectEditorTextContains(guestPage, ownerText, 60_000);
      const guestText = `guest-memory-round-${round}`;
      await typeInVisibleEditor(guestPage, `\n${guestText}`);
      await expectEditorTextContains(ownerPage, guestText, 60_000);
      await logMemorySample("edit", round + 1);
    }

    for (let round = 0; round < reloadRounds; round += 1) {
      await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
      await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
        timeout: 60_000,
      });
      await expectEditorTextContains(guestPage, "owner-content-before-idle", 60_000);
      await waitForShareEditor(guestPage, shareLink);
      await waitForEditableEditorSurface(guestPage);
      await waitForDocumentSyncReady(guestPage);
      await logMemorySample("reload", round + 1);
    }

    console.log(
      `[share-cpu-open-idle-start] idleMs=${idleMs} editRounds=${editRounds} reloadRounds=${reloadRounds}`,
    );
    const startedAt = Date.now();
    let sampleIndex = 0;
    while (Date.now() - startedAt < idleMs) {
      await logMemorySample("idle", sampleIndex);
      sampleIndex += 1;
      await guestPage.waitForTimeout(
        Math.min(sampleEveryMs, Math.max(0, idleMs - (Date.now() - startedAt))),
      );
    }
    console.log("[share-cpu-open-idle-end]");

    await expectNoVisibleShareRouteError(ownerPage);
    await expectNoVisibleShareRouteError(guestPage);
    const maxObservedHeapTotalMb = Math.max(
      ...memorySamples.flatMap((sample) => [
        sample.owner.jsHeapTotalMb,
        sample.guest.jsHeapTotalMb,
      ]),
    );
    const lastMemorySample = memorySamples[memorySamples.length - 1];
    expect(maxObservedHeapTotalMb).toBeLessThanOrEqual(maxHeapTotalMb);
    expect(lastMemorySample?.owner.documents).toBeLessThanOrEqual(maxDocumentsAfterIdle);
    expect(lastMemorySample?.guest.documents).toBeLessThanOrEqual(maxDocumentsAfterIdle);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncMessages(activeDiagnostics.messages)).toEqual([]);
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } finally {
    diagnostics?.stop();
    await guestContext.close().catch(() => {});
    await ownerContext.close().catch(() => {});
  }
});

test("anonymous edit share open does not fail owner verification", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Owner Verification");
    await openDocument(ownerPage, "Anonymous Share Owner Verification");
    await typeInVisibleEditor(ownerPage, "owner-content-before-guest-open");
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Owner Verification",
    );
    await expectNoDocumentSecurityFailure(ownerPage);
    await observeDocumentSecurityFailures(ownerPage, currentDocumentId(ownerPage));

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await expectEditorTextContains(guestPage, "owner-content-before-guest-open", 60_000);
    await guestPage.waitForTimeout(2_000);

    const guestSyncPerf = await readSyncPerf(guestPage);
    const guestState = await guestPage.evaluate(
      (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
      currentDocumentId(guestPage),
    );
    expect(
      durableMutationPerfEvents(guestSyncPerf),
      `guest open produced durable mutation events\nstate=${JSON.stringify(
        guestState,
      )}\nsyncPerf=${JSON.stringify(guestSyncPerf)}`,
    ).toEqual([]);
    await expectNoObservedDocumentSecurityFailure(ownerPage);
    await expectNoDocumentSecurityFailure(ownerPage);
    await expectWritableEditor(ownerPage);
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...guestSyncPerf];
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
            securityFailures:
              (
                window as Window & {
                  __refmdE2ESecurityFailures?: unknown[];
                }
              ).__refmdE2ESecurityFailures ?? [],
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
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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

test("anonymous edit share keeps syncing across burst edits and reload", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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

    await expectRealtimeTextPropagation(ownerPage, guestPage, "owner-low-latency-edit");
    await expectRealtimeTextPropagation(guestPage, ownerPage, "guest-low-latency-edit");
    await expectRealtimeTextPropagationViaEditorInput(
      ownerPage,
      guestPage,
      "owner-editor-low-latency-edit",
    );
    await expectRealtimeTextPropagationViaEditorInput(
      guestPage,
      ownerPage,
      "guest-editor-low-latency-edit",
    );

    await typeLineBurst(guestPage, "guest-edit", 120);
    await expectEditorTextContains(ownerPage, "guest-edit-119", 90_000).catch(async (error) => {
      const ownerDocumentId = currentDocumentId(ownerPage);
      const guestDocumentId = currentDocumentId(guestPage);
      const [ownerState, guestState, ownerPerf, guestPerf, ownerVisible, guestVisible] =
        await Promise.all([
          ownerPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            ownerDocumentId,
          ),
          guestPage.evaluate(
            (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
            guestDocumentId,
          ),
          readSyncPerf(ownerPage),
          readSyncPerf(guestPage),
          readLatencyVisibleEditorText(ownerPage).catch(String),
          readLatencyVisibleEditorText(guestPage).catch(String),
        ]);
      throw new Error(
        [
          `guest burst did not become visible on owner: ${String(error)}`,
          `owner-state: ${JSON.stringify(ownerState)}`,
          `guest-state: ${JSON.stringify(guestState)}`,
          `owner-visible: ${JSON.stringify(ownerVisible)}`,
          `guest-visible: ${JSON.stringify(guestVisible)}`,
          `owner-sync-perf: ${JSON.stringify(ownerPerf)}`,
          `guest-sync-perf: ${JSON.stringify(guestPerf)}`,
        ].join("\n"),
      );
    });
    await expectNoDocumentSecurityFailure(ownerPage);
    await expectWritableEditor(ownerPage);

    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForEditor(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectEditorTextContains(guestPage, "guest-edit-119", 60_000);
    await expectLastJoinMode(guestPage, "delta");

    await ownerPage.bringToFront();
    await waitForEditor(ownerPage);
    await typeInVisibleEditor(ownerPage, "owner-after-guest-reload");
    await expectEditorTextContains(ownerPage, "owner-after-guest-reload", 10_000);
    await guestPage.bringToFront();
    await expectEditorTextContains(guestPage, "owner-after-guest-reload", 60_000);

    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
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
      const ownerSyncPerf = ownerContext?.pages()[0]
        ? await readSyncPerf(ownerContext.pages()[0]!)
        : [];
      const guestSyncPerf = guestContext?.pages()[0]
        ? await readSyncPerf(guestContext.pages()[0]!)
        : [];
      await testInfo.attach("sync-diagnostics", {
        body: [
          "sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
          `owner-sync-perf: ${JSON.stringify(ownerSyncPerf)}`,
          `guest-sync-perf: ${JSON.stringify(guestSyncPerf)}`,
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

test("anonymous edit share preserves exact text for existing-line edits", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const initialText = "# aiueo\n\nai\n\naaaaa";
  const ownerEditedText = "# aiueo\n\naiueo\n\nkakikukeko\n\naaaaa";
  const guestEditedText = "# aiueo\n\naiueo\n\nkakikukeko-guest\n\naaaaa";
  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Exact Existing Line Sync");
    await openDocument(ownerPage, "Anonymous Share Exact Existing Line Sync");
    await replaceMarkdownEditorTextByKeyboard(ownerPage, initialText);
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Exact Existing Line Sync",
    );

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await waitForDocumentWriteSessionReady(ownerPage, { requireWriteSessionReady: true });
    await waitForDocumentWriteSessionReady(guestPage, { requireWriteSessionReady: true });
    await ensureSplitEditor(ownerPage);
    await ensureSplitEditor(guestPage);
    await expectVisibleMarkdownEditorTextEquals(guestPage, initialText, 60_000);
    await expectDocumentStateTextEquals(guestPage, initialText, 60_000);

    await ownerPage.bringToFront();
    await clickVisibleMarkdownLineEnd(ownerPage, "ai");
    await ownerPage.keyboard.insertText("ueo");
    await ownerPage.keyboard.press("Enter");
    await ownerPage.keyboard.press("Enter");
    await ownerPage.keyboard.insertText("kakikukeko");
    const ownerEditStartedAt = Date.now();
    await guestPage.bringToFront();
    const ownerToGuestVisible = expectVisibleMarkdownEditorTextEqualsSince(
      guestPage,
      ownerEditedText,
      ownerEditStartedAt,
    );
    const ownerToGuestState = expectDocumentStateTextEqualsSince(
      guestPage,
      ownerEditedText,
      ownerEditStartedAt,
    );
    const [ownerToGuestVisibleMs, ownerToGuestStateMs] = await Promise.all([
      ownerToGuestVisible,
      ownerToGuestState,
    ]).catch(async (error) => {
      await logExactTextSyncDiagnostics("owner-to-guest-timeout", ownerPage, guestPage);
      throw error;
    });
    await expectVisibleMarkdownEditorTextEquals(ownerPage, ownerEditedText, 5_000);
    console.log(
      `[share-exact-existing-line] direction=owner-to-guest visibleMs=${ownerToGuestVisibleMs} stateMs=${ownerToGuestStateMs}`,
    );

    await guestPage.bringToFront();
    await clickVisibleMarkdownLineEnd(guestPage, "kakikukeko");
    await guestPage.keyboard.insertText("-guest");
    const guestEditStartedAt = Date.now();
    await ownerPage.bringToFront();
    const guestToOwnerVisible = expectVisibleMarkdownEditorTextEqualsSince(
      ownerPage,
      guestEditedText,
      guestEditStartedAt,
    );
    const guestToOwnerState = expectDocumentStateTextEqualsSince(
      ownerPage,
      guestEditedText,
      guestEditStartedAt,
    );
    const [guestToOwnerVisibleMs, guestToOwnerStateMs] = await Promise.all([
      guestToOwnerVisible,
      guestToOwnerState,
    ]).catch(async (error) => {
      await logExactTextSyncDiagnostics("guest-to-owner-timeout", ownerPage, guestPage);
      throw error;
    });
    await expectVisibleMarkdownEditorTextEquals(guestPage, guestEditedText, 5_000);
    console.log(
      `[share-exact-existing-line] direction=guest-to-owner visibleMs=${guestToOwnerVisibleMs} stateMs=${guestToOwnerStateMs}`,
    );

    await flushDocumentSync(ownerPage);
    await flushDocumentSync(guestPage);
    await waitForDocumentSyncReady(ownerPage);
    await waitForDocumentSyncReady(guestPage);
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
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
          `owner-visible-markdown: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-markdown: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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

test("anonymous edit share converges the whole document after trailing multiline owner edits", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const initialText = [
    "# aiueo",
    "",
    "aiueo",
    "",
    "kakikukeko",
    "",
    "sasisuseso",
    "",
    "tatituteto",
    "",
    "naninuneno",
    "",
    "oooo",
    "",
    "omaeha dareda?",
  ].join("\n");
  const trailingOwnerAppend = "\n\naaaa\n\naiueo\n\nkakikujejo";
  const trailingOwnerAppendParagraphs = ["aaaa", "aiueo", "kakikujejo"];
  const ownerExtendedText = `${initialText}${trailingOwnerAppend}`;
  const guestAppend = "\n\nguest whole-document tail";
  const guestAppendParagraphs = ["guest whole-document tail"];
  const guestExtendedText = `${ownerExtendedText}${guestAppend}`;
  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Whole Document Convergence");
    await openDocument(ownerPage, "Anonymous Share Whole Document Convergence");
    await replaceMarkdownEditorTextByKeyboard(ownerPage, initialText);
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Whole Document Convergence",
    );

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await waitForDocumentWriteSessionReady(ownerPage, { requireWriteSessionReady: true });
    await waitForDocumentWriteSessionReady(guestPage, { requireWriteSessionReady: true });
    await ensureSplitEditor(ownerPage);
    await ensureSplitEditor(guestPage);
    await expectNoContentPreviewOverlay(ownerPage);
    await expectNoContentPreviewOverlay(guestPage);
    await expectVisibleMarkdownEditorTextEquals(guestPage, initialText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, initialText, 60_000);
    await expectDocumentStateTextEquals(guestPage, initialText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(guestPage, initialText, 60_000);

    await ownerPage.bringToFront();
    await clickVisibleMarkdownLineEnd(ownerPage, "omaeha dareda?");
    await appendMarkdownParagraphsByKeyboard(ownerPage, trailingOwnerAppendParagraphs);
    await expectVisibleMarkdownEditorTextEquals(ownerPage, ownerExtendedText, 5_000);
    await expectRegisteredEditorValuesEqual(ownerPage, ownerExtendedText, 5_000);
    await expectDocumentStateTextEquals(ownerPage, ownerExtendedText, 5_000);
    const ownerAppendLocalReadyAt = Date.now();
    await guestPage.bringToFront();
    const [
      ownerToGuestStateMs,
      ownerToGuestMarkdownMs,
      ownerToGuestRegisteredMs,
      ownerToGuestWysiwygMs,
    ] = await Promise.all([
      expectDocumentStateTextEqualsSince(guestPage, ownerExtendedText, ownerAppendLocalReadyAt),
      expectVisibleMarkdownEditorTextEqualsSince(
        guestPage,
        ownerExtendedText,
        ownerAppendLocalReadyAt,
      ),
      expectRegisteredEditorValuesEqualSince(guestPage, ownerExtendedText, ownerAppendLocalReadyAt),
      expectVisibleProseMirrorContainsMarkdownTextSince(
        guestPage,
        ownerExtendedText,
        ownerAppendLocalReadyAt,
      ),
    ]);
    console.log(
      `[share-whole-document-converged] direction=owner-to-guest stateMs=${ownerToGuestStateMs} markdownMs=${ownerToGuestMarkdownMs} registeredMs=${ownerToGuestRegisteredMs} wysiwygMs=${ownerToGuestWysiwygMs}`,
    );

    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await ensureSplitEditor(guestPage);
    await expectNoContentPreviewOverlay(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectVisibleMarkdownEditorTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, ownerExtendedText, 60_000);
    await expectDocumentStateTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(guestPage, ownerExtendedText, 60_000);

    await guestPage.bringToFront();
    await clickVisibleMarkdownLineEnd(guestPage, "kakikujejo");
    await appendMarkdownParagraphsByKeyboard(guestPage, guestAppendParagraphs);
    await expectVisibleMarkdownEditorTextEquals(guestPage, guestExtendedText, 5_000);
    await expectRegisteredEditorValuesEqual(guestPage, guestExtendedText, 5_000);
    await expectDocumentStateTextEquals(guestPage, guestExtendedText, 5_000);
    const guestAppendLocalReadyAt = Date.now();
    await ownerPage.bringToFront();
    const [
      guestToOwnerStateMs,
      guestToOwnerMarkdownMs,
      guestToOwnerRegisteredMs,
      guestToOwnerWysiwygMs,
    ] = await Promise.all([
      expectDocumentStateTextEqualsSince(ownerPage, guestExtendedText, guestAppendLocalReadyAt),
      expectVisibleMarkdownEditorTextEqualsSince(
        ownerPage,
        guestExtendedText,
        guestAppendLocalReadyAt,
      ),
      expectRegisteredEditorValuesEqualSince(ownerPage, guestExtendedText, guestAppendLocalReadyAt),
      expectVisibleProseMirrorContainsMarkdownTextSince(
        ownerPage,
        guestExtendedText,
        guestAppendLocalReadyAt,
      ),
    ]);
    console.log(
      `[share-whole-document-converged] direction=guest-to-owner stateMs=${guestToOwnerStateMs} markdownMs=${guestToOwnerMarkdownMs} registeredMs=${guestToOwnerRegisteredMs} wysiwygMs=${guestToOwnerWysiwygMs}`,
    );

    await flushDocumentSync(ownerPage);
    await flushDocumentSync(guestPage);
    await waitForDocumentSyncReady(ownerPage);
    await waitForDocumentSyncReady(guestPage);
    await expectDocumentSavedStateTextEquals(ownerPage, guestExtendedText, 5_000);
    await expectDocumentSavedStateTextEquals(guestPage, guestExtendedText, 5_000);
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      await testInfo.attach("whole-document-sync-diagnostics", {
        body: [
          "whole document sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
          `owner-visible-markdown: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-markdown: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-visible-wysiwyg: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleProseMirrorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-wysiwyg: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleProseMirrorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-state: ${JSON.stringify(
            ownerContext?.pages()[0] && currentDocumentIdOrNull(ownerContext.pages()[0]!)
              ? await ownerContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(ownerContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `guest-state: ${JSON.stringify(
            guestContext?.pages()[0] && currentDocumentIdOrNull(guestContext.pages()[0]!)
              ? await guestContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(guestContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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

test("anonymous edit share converges owner edits made during share bootstrap", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const initialText = [
    "# bootstrap race",
    "",
    "aiueo",
    "",
    "kakikukeko",
    "",
    "sasisuseso",
    "",
    "tatituteto",
    "",
    "naninuneno",
    "",
    "oooo",
    "",
    "omaeha dareda?",
  ].join("\n");
  const trailingOwnerAppendParagraphs = ["aaaa", "aiueo", "kakikujejo"];
  const ownerExtendedText = `${initialText}\n\naaaa\n\naiueo\n\nkakikujejo`;
  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Bootstrap Race Convergence");
    await openDocument(ownerPage, "Anonymous Share Bootstrap Race Convergence");
    await replaceMarkdownEditorTextByKeyboard(ownerPage, initialText);
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Bootstrap Race Convergence",
    );

    const guestOpen = guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await guestOpen;
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });

    await ownerPage.bringToFront();
    await ensureSplitEditor(ownerPage);
    await expectNoContentPreviewOverlay(ownerPage);
    await clickVisibleMarkdownLineEnd(ownerPage, "omaeha dareda?");
    await appendMarkdownParagraphsByKeyboard(ownerPage, trailingOwnerAppendParagraphs);
    await expectVisibleMarkdownEditorTextEquals(ownerPage, ownerExtendedText, 5_000);
    await expectRegisteredEditorValuesEqual(ownerPage, ownerExtendedText, 5_000);
    await expectDocumentStateTextEquals(ownerPage, ownerExtendedText, 5_000);
    await flushDocumentSync(ownerPage);
    await waitForDocumentSyncReady(ownerPage);
    await expectDocumentSavedStateTextEquals(ownerPage, ownerExtendedText, 5_000);

    await guestPage.bringToFront();
    await expect(guestPage).toHaveURL(SHARE_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await ensureSplitEditor(guestPage);
    await expectNoContentPreviewOverlay(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectVisibleMarkdownEditorTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, ownerExtendedText, 60_000);
    await expectDocumentStateTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectDocumentSavedStateTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(guestPage, ownerExtendedText, 60_000);
    await expectLastJoinMode(guestPage, "delta");

    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      await testInfo.attach("bootstrap-race-sync-diagnostics", {
        body: [
          "bootstrap race sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
          `owner-visible-markdown: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-markdown: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-state: ${JSON.stringify(
            ownerContext?.pages()[0] && currentDocumentIdOrNull(ownerContext.pages()[0]!)
              ? await ownerContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(ownerContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `guest-state: ${JSON.stringify(
            guestContext?.pages()[0] && currentDocumentIdOrNull(guestContext.pages()[0]!)
              ? await guestContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(guestContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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

test("anonymous edit share converges whole-document WYSIWYG paragraph edits", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const initialText = [
    "# wysiwyg convergence",
    "",
    "aiueo",
    "",
    "kakikukeko",
    "",
    "sasisuseso",
    "",
    "tatituteto",
    "",
    "naninuneno",
    "",
    "oooo",
    "",
    "omaeha dareda?",
  ].join("\n");
  const ownerAppendParagraphs = ["aaaa", "aiueo", "kakikujejo"];
  const ownerExtendedText = `${initialText}\naaaa\naiueo\nkakikujejo`;
  const guestAppendParagraphs = ["guest wysiwyg tail"];
  const guestExtendedText = `${ownerExtendedText}\nguest wysiwyg tail`;
  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share WYSIWYG Whole Document Convergence");
    await openDocument(ownerPage, "Anonymous Share WYSIWYG Whole Document Convergence");
    await replaceMarkdownEditorTextByKeyboard(ownerPage, initialText);
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share WYSIWYG Whole Document Convergence",
    );

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await waitForDocumentWriteSessionReady(ownerPage, { requireWriteSessionReady: true });
    await waitForDocumentWriteSessionReady(guestPage, { requireWriteSessionReady: true });
    await ensureSplitEditor(ownerPage);
    await ensureSplitEditor(guestPage);
    await expectNoContentPreviewOverlay(ownerPage);
    await expectNoContentPreviewOverlay(guestPage);
    await expectRegisteredEditorValuesEqual(ownerPage, initialText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, initialText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(ownerPage, initialText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(guestPage, initialText, 60_000);

    await ownerPage.bringToFront();
    await switchToWysiwygOnly(ownerPage);
    await appendProseMirrorParagraphsByKeyboard(ownerPage, ownerAppendParagraphs);
    await ensureSplitEditor(ownerPage);
    await expectRegisteredEditorValuesEqual(ownerPage, ownerExtendedText, 5_000);
    await expectVisibleMarkdownEditorTextEquals(ownerPage, ownerExtendedText, 5_000);
    await expectDocumentStateTextEquals(ownerPage, ownerExtendedText, 5_000);
    const ownerAppendLocalReadyAt = Date.now();
    await guestPage.bringToFront();
    const [
      ownerToGuestStateMs,
      ownerToGuestMarkdownMs,
      ownerToGuestRegisteredMs,
      ownerToGuestWysiwygMs,
    ] = await Promise.all([
      expectDocumentStateTextEqualsSince(guestPage, ownerExtendedText, ownerAppendLocalReadyAt),
      expectVisibleMarkdownEditorTextEqualsSince(
        guestPage,
        ownerExtendedText,
        ownerAppendLocalReadyAt,
      ),
      expectRegisteredEditorValuesEqualSince(guestPage, ownerExtendedText, ownerAppendLocalReadyAt),
      expectVisibleProseMirrorContainsMarkdownTextSince(
        guestPage,
        ownerExtendedText,
        ownerAppendLocalReadyAt,
      ),
    ]);
    console.log(
      `[share-wysiwyg-whole-document-converged] direction=owner-to-guest stateMs=${ownerToGuestStateMs} markdownMs=${ownerToGuestMarkdownMs} registeredMs=${ownerToGuestRegisteredMs} wysiwygMs=${ownerToGuestWysiwygMs}`,
    );

    await flushDocumentSync(ownerPage);
    await waitForDocumentSyncReady(ownerPage);
    await expectDocumentSavedStateTextEquals(ownerPage, ownerExtendedText, 5_000);
    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await ensureSplitEditor(guestPage);
    await expectNoContentPreviewOverlay(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectDocumentStateTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectDocumentSavedStateTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, ownerExtendedText, 60_000);
    await expectVisibleMarkdownEditorTextEquals(guestPage, ownerExtendedText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(guestPage, ownerExtendedText, 60_000);

    await guestPage.bringToFront();
    await switchToWysiwygOnly(guestPage);
    await appendProseMirrorParagraphsByKeyboard(guestPage, guestAppendParagraphs);
    await ensureSplitEditor(guestPage);
    await expectRegisteredEditorValuesEqual(guestPage, guestExtendedText, 5_000);
    await expectVisibleMarkdownEditorTextEquals(guestPage, guestExtendedText, 5_000);
    await expectDocumentStateTextEquals(guestPage, guestExtendedText, 5_000);
    const guestAppendLocalReadyAt = Date.now();
    await ownerPage.bringToFront();
    const [
      guestToOwnerStateMs,
      guestToOwnerMarkdownMs,
      guestToOwnerRegisteredMs,
      guestToOwnerWysiwygMs,
    ] = await Promise.all([
      expectDocumentStateTextEqualsSince(ownerPage, guestExtendedText, guestAppendLocalReadyAt),
      expectVisibleMarkdownEditorTextEqualsSince(
        ownerPage,
        guestExtendedText,
        guestAppendLocalReadyAt,
      ),
      expectRegisteredEditorValuesEqualSince(ownerPage, guestExtendedText, guestAppendLocalReadyAt),
      expectVisibleProseMirrorContainsMarkdownTextSince(
        ownerPage,
        guestExtendedText,
        guestAppendLocalReadyAt,
      ),
    ]);
    console.log(
      `[share-wysiwyg-whole-document-converged] direction=guest-to-owner stateMs=${guestToOwnerStateMs} markdownMs=${guestToOwnerMarkdownMs} registeredMs=${guestToOwnerRegisteredMs} wysiwygMs=${guestToOwnerWysiwygMs}`,
    );

    await flushDocumentSync(ownerPage);
    await flushDocumentSync(guestPage);
    await waitForDocumentSyncReady(ownerPage);
    await waitForDocumentSyncReady(guestPage);
    await expectDocumentSavedStateTextEquals(ownerPage, guestExtendedText, 5_000);
    await expectDocumentSavedStateTextEquals(guestPage, guestExtendedText, 5_000);
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      await testInfo.attach("wysiwyg-whole-document-sync-diagnostics", {
        body: [
          "wysiwyg whole document sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
          `owner-registered-editors: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readRegisteredEditorValues(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-registered-editors: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readRegisteredEditorValues(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-visible-markdown: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-markdown: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-visible-wysiwyg: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleProseMirrorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-wysiwyg: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleProseMirrorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-state: ${JSON.stringify(
            ownerContext?.pages()[0] && currentDocumentIdOrNull(ownerContext.pages()[0]!)
              ? await ownerContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(ownerContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `guest-state: ${JSON.stringify(
            guestContext?.pages()[0] && currentDocumentIdOrNull(guestContext.pages()[0]!)
              ? await guestContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(guestContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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

test("anonymous edit share reload reentry does not keep a stale whole document", async ({
  browser,
}, testInfo) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const initialText = [
    "# reentry convergence",
    "",
    "stale-only-before-owner-save",
    "",
    "aiueo",
    "",
    "omaeha dareda?",
  ].join("\n");
  const latestText = [
    "# reentry convergence",
    "",
    "latest-after-owner-save",
    "",
    "aiueo",
    "",
    "omaeha dareda?",
    "",
    "aaaa",
    "",
    "aiueo",
    "",
    "kakikujejo",
  ].join("\n");
  let ownerContext: BrowserContext | undefined;
  let guestContext: BrowserContext | undefined;
  let diagnostics: ReturnType<typeof collectSyncDiagnostics> | undefined;

  try {
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await createDocument(ownerPage, "Anonymous Share Reentry Whole Document Convergence");
    await openDocument(ownerPage, "Anonymous Share Reentry Whole Document Convergence");
    await replaceMarkdownEditorTextByKeyboard(ownerPage, initialText);
    await expectDocumentSavedStateTextEquals(ownerPage, initialText, 5_000);
    const shareLink = await createEditShareLinkFromUi(
      ownerPage,
      "Anonymous Share Reentry Whole Document Convergence",
    );

    await guestPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await ensureSplitEditor(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectNoContentPreviewOverlay(guestPage);
    await expectDocumentStateTextEquals(guestPage, initialText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, initialText, 60_000);

    await ownerPage.bringToFront();
    await replaceMarkdownEditorTextByKeyboard(ownerPage, latestText);
    await flushDocumentSync(ownerPage);
    await waitForDocumentSyncReady(ownerPage);
    await expectDocumentSavedStateTextEquals(ownerPage, latestText, 5_000);

    await guestPage.bringToFront();
    await guestPage.reload({ waitUntil: "domcontentloaded" });
    await expect(guestPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(guestPage, shareLink);
    await ensureSplitEditor(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectNoContentPreviewOverlay(guestPage);
    await expectDocumentStateTextEquals(guestPage, latestText, 60_000);
    await expectDocumentSavedStateTextEquals(guestPage, latestText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, latestText, 60_000);
    await expectVisibleMarkdownEditorTextEquals(guestPage, latestText, 60_000);
    await expectVisibleProseMirrorContainsMarkdownText(guestPage, latestText, 60_000);
    const guestVisibleAfterReload = await readVisibleEditorSurfaceText(guestPage);
    expect(guestVisibleAfterReload).not.toContain("stale-only-before-owner-save");
    const guestStateAfterReload = await readDocumentSyncStateText(guestPage);
    expect(guestStateAfterReload).not.toContain("stale-only-before-owner-save");

    await guestPage.goto(guestPage.url(), { waitUntil: "domcontentloaded" });
    await waitForShareEditor(guestPage, shareLink);
    await ensureSplitEditor(guestPage);
    await waitForDocumentSyncReady(guestPage);
    await expectDocumentStateTextEquals(guestPage, latestText, 60_000);
    await expectRegisteredEditorValuesEqual(guestPage, latestText, 60_000);
    await expectVisibleMarkdownEditorTextEquals(guestPage, latestText, 60_000);

    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerPageSnapshot = ownerContext?.pages()[0]
        ? await ownerContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestContext?.pages()[0]
        ? await guestContext.pages()[0]!.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 4000) ?? "",
          }))
        : null;
      await testInfo.attach("reentry-whole-document-sync-diagnostics", {
        body: [
          "reentry whole document sync diagnostics:",
          ...diagnostics.messages.map((message) => `- ${message}`),
          `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
          `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
          `owner-registered-editors: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readRegisteredEditorValues(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-registered-editors: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readRegisteredEditorValues(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-visible-markdown: ${JSON.stringify(
            ownerContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(ownerContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `guest-visible-markdown: ${JSON.stringify(
            guestContext?.pages()[0]
              ? await readVisibleMarkdownEditorText(guestContext.pages()[0]!).catch(String)
              : null,
          )}`,
          `owner-state: ${JSON.stringify(
            ownerContext?.pages()[0] && currentDocumentIdOrNull(ownerContext.pages()[0]!)
              ? await ownerContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(ownerContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `guest-state: ${JSON.stringify(
            guestContext?.pages()[0] && currentDocumentIdOrNull(guestContext.pages()[0]!)
              ? await guestContext
                  .pages()[0]!
                  .evaluate(
                    (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                    currentDocumentId(guestContext.pages()[0]!),
                  )
                  .catch(String)
              : null,
          )}`,
          `owner-sync-perf: ${JSON.stringify(
            ownerContext?.pages()[0] ? await readSyncPerf(ownerContext.pages()[0]!) : [],
          )}`,
          `guest-sync-perf: ${JSON.stringify(
            guestContext?.pages()[0] ? await readSyncPerf(guestContext.pages()[0]!) : [],
          )}`,
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
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    guestContext = await newStrictShareContext(browser, {
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
    await guestContext.routeWebSocket(
      (url) => url.pathname.startsWith("/api/socket"),
      (socket) => {
        guestSockets.push(socket);
        if (!allowGuestSocket) {
          void socket.close({ code: 1001 });
          return;
        }
        socket.connectToServer();
      },
    );
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
    await expectEditorTextContains(guestPage, "owner-after-manual-anonymous-edit", 60_000);

    const finalSyncPerf = [...(await readSyncPerf(ownerPage)), ...(await readSyncPerf(guestPage))];
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
  } catch (err) {
    if (diagnostics) {
      const ownerFailurePage = ownerContext?.pages()[0];
      const guestFailurePage = guestContext?.pages()[0];
      const ownerFailureDocumentId = ownerFailurePage
        ? currentDocumentIdOrNull(ownerFailurePage)
        : null;
      const guestFailureDocumentId = guestFailurePage
        ? currentDocumentIdOrNull(guestFailurePage)
        : null;
      const ownerPageSnapshot = ownerFailurePage
        ? await ownerFailurePage.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      const guestPageSnapshot = guestFailurePage
        ? await guestFailurePage.evaluate(() => ({
            url: window.location.href,
            text: document.body.textContent?.slice(0, 2000) ?? "",
          }))
        : null;
      const [ownerState, guestState, ownerPerf, guestPerf, ownerVisible, guestVisible] =
        await Promise.all([
          ownerFailurePage && ownerFailureDocumentId
            ? ownerFailurePage.evaluate(
                (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                ownerFailureDocumentId,
              )
            : Promise.resolve(null),
          guestFailurePage && guestFailureDocumentId
            ? guestFailurePage.evaluate(
                (id) => window.__refmdGetDocumentSyncState?.(id) ?? null,
                guestFailureDocumentId,
              )
            : Promise.resolve(null),
          ownerFailurePage ? readSyncPerf(ownerFailurePage) : Promise.resolve([]),
          guestFailurePage ? readSyncPerf(guestFailurePage) : Promise.resolve([]),
          ownerFailurePage
            ? readLatencyVisibleEditorText(ownerFailurePage).catch(String)
            : Promise.resolve(null),
          guestFailurePage
            ? readLatencyVisibleEditorText(guestFailurePage).catch(String)
            : Promise.resolve(null),
        ]);
      const diagnosticText = [
        "sync diagnostics:",
        ...diagnostics.messages.map((message) => `- ${message}`),
        `owner-page: ${JSON.stringify(ownerPageSnapshot)}`,
        `guest-page: ${JSON.stringify(guestPageSnapshot)}`,
        `owner-state: ${JSON.stringify(ownerState)}`,
        `guest-state: ${JSON.stringify(guestState)}`,
        `owner-visible: ${JSON.stringify(ownerVisible)}`,
        `guest-visible: ${JSON.stringify(guestVisible)}`,
        `owner-sync-perf: ${JSON.stringify(ownerPerf)}`,
        `guest-sync-perf: ${JSON.stringify(guestPerf)}`,
      ].join("\n");
      await testInfo.attach("sync-diagnostics", {
        body: diagnosticText,
        contentType: "text/plain",
      });
      throw new Error(`${String(err)}\n${diagnosticText}`);
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
    ownerContext = await newStrictShareContext(browser, {
      acceptDownloads: true,
    });
    recipientContext = await newStrictShareContext(browser, {
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
    const shareLink = await createEditShareLinkFromUi(ownerPage, LOGGED_IN_DOC_TITLE);

    await registerAccount(recipientPage, "Logged In Share Recipient");
    await recipientPage.goto(shareLink, { waitUntil: "domcontentloaded" });
    await expect(recipientPage).toHaveURL(SHARE_ENTRY_OR_DOCUMENT_ROUTE_RE, {
      timeout: 60_000,
    });
    await waitForShareEditor(recipientPage, shareLink);

    await typeInVisibleEditor(recipientPage, "logged-in-share-edit");
    await expectEditorTextContains(ownerPage, "logged-in-share-edit", 60_000);

    await typeInVisibleEditor(ownerPage, "owner-after-logged-in-share-edit");
    await expectEditorTextContains(recipientPage, "owner-after-logged-in-share-edit", 60_000);

    const finalSyncPerf = [
      ...(await readSyncPerf(ownerPage)),
      ...(await readSyncPerf(recipientPage)),
    ];
    expect(criticalSyncMessages(diagnostics.messages)).toEqual([]);
    expect(criticalSyncPerfEvents(finalSyncPerf)).toEqual([]);
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
