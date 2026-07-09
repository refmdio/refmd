import {
  test,
  expect,
  type BrowserContext,
  type Page,
  type Request,
} from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_TIMEOUTS } from "../../support/timeouts";

type CaptureWindow = Window & {
  __REFMD_E2E__?: boolean;
  __refmdWsSends?: string[];
};

async function installWebSocketCapture(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const win = window as CaptureWindow;
    win.__REFMD_E2E__ = true;
    win.__refmdWsSends = [];

    const proto = WebSocket.prototype as WebSocket & {
      __refmdCaptureInstalled?: boolean;
    };
    if (proto.__refmdCaptureInstalled) return;

    const originalSend = WebSocket.prototype.send;
    proto.__refmdCaptureInstalled = true;

    WebSocket.prototype.send = function (
      this: WebSocket,
      data: string | ArrayBufferLike | Blob | ArrayBufferView,
    ): void {
      try {
        const target = window as CaptureWindow;
        target.__refmdWsSends ??= [];
        target.__refmdWsSends.push(
          typeof data === "string" ? data : "[binary websocket frame]",
        );
      } catch {
        // Keep the capture diagnostic from changing WebSocket behavior.
      }
      originalSend.call(this, data);
    };
  });
}

function captureApiMutations(page: Page, bodies: string[]): (request: Request) => void {
  return (request) => {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(request.method())) return;

    const url = new URL(request.url());
    if (!url.pathname.startsWith("/api/")) return;

    const postData = request.postData();
    if (postData) bodies.push(`${request.method()} ${url.pathname} ${postData}`);
  };
}

async function clearWebSocketCapture(page: Page): Promise<void> {
  await page.evaluate(() => {
    (window as CaptureWindow).__refmdWsSends = [];
  });
}

async function readWebSocketCapture(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as CaptureWindow).__refmdWsSends ?? []);
}

function currentDocumentId(page: Page): string {
  const match = page.url().match(/\/document\/([^/?#]+)/);
  if (!match) throw new Error(`current path is not a document route: ${page.url()}`);
  return match[1];
}

async function waitForDocumentSaveIdle(page: Page, documentId: string): Promise<void> {
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
        timeout: 90_000,
        message: `document sync did not settle: ${JSON.stringify(states.slice(-5))}`,
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

test("document create and sync traffic does not include plaintext document data", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.extendedScenario);

  const context = await newE2EContext(browser, { bypassCSP: true });
  await installWebSocketCapture(context);
  const page = await context.newPage();

  try {
    await registerAccount(page);
    await clearWebSocketCapture(page);

    const httpBodies: string[] = [];
    const captureRequest = captureApiMutations(page, httpBodies);
    page.on("request", captureRequest);

    const title = `Transport Canary ${Date.now()}`;
    const body = `transport-canary-${crypto.randomUUID()}`;

    await createDocument(page, title);
    await openDocument(page, title);

    const editor = page.locator(".cm-content");
    await expect(editor).toBeVisible({ timeout: 30_000 });
    await editor.click();
    await page.keyboard.insertText(body);
    await expectEditorTextContains(page, body, 30_000);
    const documentId = currentDocumentId(page);
    expect(documentId).toMatch(/[0-9a-f-]{36}/);
    await waitForDocumentSaveIdle(page, documentId);

    page.off("request", captureRequest);
    const outboundPayloads = [...httpBodies, ...(await readWebSocketCapture(page))];
    expect(outboundPayloads.length).toBeGreaterThan(0);
    expect(
      outboundPayloads.some(
        (payload) => payload.includes("encrypted_title") || payload.includes("ciphertext"),
      ),
    ).toBe(true);

    for (const marker of [title, body]) {
      expect(
        outboundPayloads.filter((payload) => payload.includes(marker)),
        `outbound payloads must not contain plaintext marker ${marker}`,
      ).toEqual([]);
    }
  } finally {
    await context.close();
  }
});
